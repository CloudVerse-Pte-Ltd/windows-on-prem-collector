import { randomUUID } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { HypervCimInventoryAdapter } from '../hyperv/cim-inventory.js'
import { toHypervCollectionPayload, toHypervInventoryEnvelope, toHypervTelemetryEnvelope } from '../hyperv/canonical-envelope.js'
import { normalizeHypervPerformanceOutput, type HypervMetricFact, type HypervMetricGap } from '../hyperv/performance.js'
import { ScvmmInventoryAdapter } from '../scvmm/inventory.js'
import { ConstrainedPowerShellRunner } from '../security/powershell-runner.js'
import { EncryptedWindowsSpool, WindowsSpoolUploader, WINDOWS_ACCEPTED_BUNDLE_SCHEMAS } from './encrypted-spool.js'
import { statePaths, type WindowsCollectorIdentity } from './enrollment.js'
import { WindowsBundleSigner } from './signed-bundle.js'
import { collectionFailureHealth, collectionSuccessHealth, initialRuntimeHealth, RuntimeHealthStore, type CollectorRuntimeHealth } from './runtime-health.js'

export type WindowsCollectorScaleClass = 'S' | 'M' | 'L' | 'XL'
const WINDOWS_SPOOL_CEILINGS: Readonly<Record<WindowsCollectorScaleClass, number>> = Object.freeze({ S: 10 * 1_073_741_824, M: 50 * 1_073_741_824, L: 200 * 1_073_741_824, XL: 500 * 1_073_741_824 })
export interface WindowsCollectorConfig { stateDirectory: string; spoolDirectory: string; scriptsDirectory: string; manifestPath: string; managementPlaneUid: string; mode: 'SCVMM' | 'LOCAL_HYPERV'; scaleClass: WindowsCollectorScaleClass; executionBoundary: { kind: 'JEA'; endpointName: string } | { kind: 'WDAC_APPLOCKER' }; scvmm?: { server: string; port: number }; upload?: { endpoint: string; allowedHosts: string[]; privateAddressAllowedHosts?: string[]; proxy?: { endpoint: string; allowedHosts: string[]; privateAddressAllowedHosts?: string[]; authorizationFile: string } }; intervalSeconds: number; maxSpoolBytes: number; maxSpoolItems: number; offlineExportDirectory?: string }
export async function loadWindowsCollectorConfig(path: string): Promise<WindowsCollectorConfig> {
  const value = JSON.parse(await readFile(path, 'utf8')) as WindowsCollectorConfig
  if (!['SCVMM', 'LOCAL_HYPERV'].includes(value.mode) || !Number.isSafeInteger(value.intervalSeconds) || value.intervalSeconds < 60) throw new Error('Collector mode or interval is invalid')
  const spoolCeiling = WINDOWS_SPOOL_CEILINGS[value.scaleClass]
  if (!spoolCeiling) throw new Error('Collector scaleClass must be S, M, L or XL')
  if (!value.executionBoundary || !['JEA', 'WDAC_APPLOCKER'].includes(value.executionBoundary.kind)) throw new Error('An explicit JEA or WDAC/AppLocker execution boundary is required')
  if (value.executionBoundary.kind === 'JEA' && !/^[A-Za-z][A-Za-z0-9.-]{0,63}$/.test(value.executionBoundary.endpointName ?? '')) throw new Error('JEA endpoint name is invalid')
  const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
  const planePattern = new RegExp(`^${value.mode === 'SCVMM' ? 'scvmm' : 'hyperv'}:${uuid}$`, 'i')
  if (!planePattern.test(value.managementPlaneUid ?? '')) throw new Error(`Collector mode requires an immutable ${value.mode === 'SCVMM' ? 'SCVMM' : 'Hyper-V host'} management-plane UUID`)
  for (const [name, candidate] of Object.entries({ stateDirectory: value.stateDirectory, spoolDirectory: value.spoolDirectory, scriptsDirectory: value.scriptsDirectory, manifestPath: value.manifestPath })) if (typeof candidate !== 'string' || !candidate.trim()) throw new Error(`${name} is required`)
  if (!Number.isSafeInteger(value.maxSpoolBytes) || value.maxSpoolBytes <= 0 || !Number.isSafeInteger(value.maxSpoolItems) || value.maxSpoolItems <= 0) throw new Error('Positive spool bounds are required')
  if (value.maxSpoolBytes > spoolCeiling) throw new Error(`maxSpoolBytes exceeds the ratified ${value.scaleClass} scale-class ceiling`)
  if (value.mode === 'SCVMM' && (!value.scvmm || typeof value.scvmm.server !== 'string' || !value.scvmm.server.trim() || !Number.isSafeInteger(value.scvmm.port) || value.scvmm.port < 1 || value.scvmm.port > 65535)) throw new Error('SCVMM configuration is required')
  if (!value.upload && !value.offlineExportDirectory) throw new Error('Upload or offline export must be configured')
  if (value.upload && (!Array.isArray(value.upload.allowedHosts) || !value.upload.allowedHosts.length)) throw new Error('Upload allowedHosts must be non-empty')
  if (value.upload?.proxy && (!Array.isArray(value.upload.proxy.allowedHosts) || !value.upload.proxy.allowedHosts.length || typeof value.upload.proxy.authorizationFile !== 'string' || !value.upload.proxy.authorizationFile.trim())) throw new Error('Proxy allowedHosts and authorizationFile are required')
  return value
}

export async function collectPerformanceForMode(mode: WindowsCollectorConfig['mode'], runner: ConstrainedPowerShellRunner): Promise<{ facts: HypervMetricFact[]; gaps: HypervMetricGap[] }> {
  if (mode === 'LOCAL_HYPERV') return normalizeHypervPerformanceOutput(await runner.runLocalHypervPerformance())
  return { facts: [], gaps: [{ code: 'HOST_LEVEL_PERFORMANCE_COLLECTOR_REQUIRED', metricKey: 'hyperv.vm.performance', details: { inventoryTransport: 'SCVMM_POWERSHELL', localHostCountersRejected: true } }] }
}

export class WindowsCollectorRuntime {
  private health: CollectorRuntimeHealth
  constructor(private readonly config: WindowsCollectorConfig, private readonly runner: ConstrainedPowerShellRunner, private readonly spool: EncryptedWindowsSpool, private readonly signer: WindowsBundleSigner, private readonly identity: WindowsCollectorIdentity, private readonly uploader?: WindowsSpoolUploader, private readonly healthStore = new RuntimeHealthStore(config.stateDirectory), private readonly clock = () => new Date(), private readonly delay = abortableDelay) { this.health = initialRuntimeHealth(this.clock()) }
  async collectOnce(now = new Date()) { const collectionRunId = randomUUID(); const context = { connectorVersion: process.env.COLLECTOR_VERSION ?? '0.1.0', collectionRunId, collectedAt: now.toISOString() }; const inventory = this.config.mode === 'SCVMM' ? await new ScvmmInventoryAdapter(this.runner).collect(this.config.scvmm!, context) : await new HypervCimInventoryAdapter(this.runner).collect(context); const performance = await collectPerformanceForMode(this.config.mode, this.runner); const inventoryEnvelope = toHypervInventoryEnvelope(this.identity.integrationId, this.config.managementPlaneUid, inventory); const telemetryEnvelope = toHypervTelemetryEnvelope(this.identity.integrationId, this.config.managementPlaneUid, now.toISOString(), performance.facts, performance.gaps); const bundle = this.signer.create(collectionRunId, toHypervCollectionPayload(inventoryEnvelope, telemetryEnvelope, this.config.scaleClass), now); await this.spool.enqueue(bundle.bundleId, bundle.schemaVersion, Buffer.from(JSON.stringify(bundle))); return { collectionRunId, bundleId: bundle.bundleId } }
  async validate() { await this.runner.initialize(); return { valid: true as const, mode: this.config.mode, managementPlaneUid: this.config.managementPlaneUid, acceptedBundleSchemas: this.spool.acceptedSchemas() } }
  async flush() { if (this.uploader) return this.uploader.flushOnce(); if (!this.config.offlineExportDirectory) return { sent: 0 }; await mkdir(this.config.offlineExportDirectory, { recursive: true }); let sent = 0; for (const item of await this.spool.list()) { if (!this.spool.accepts(item.schemaVersion)) continue; await writeFile(join(this.config.offlineExportDirectory, `${item.queueId}.${item.bundleId}.bundle`), item.payload, { flag: 'wx', mode: 0o600 }); await this.spool.remove(item.queueId); sent++ } return { sent } }
  async run(signal?: AbortSignal) {
    this.health = await this.healthStore.read() ?? this.health
    await this.healthStore.write(this.health)
    try { await this.validate() } catch (error) { const now = this.clock(); this.health = collectionFailureHealth(this.health, now, now, error); await this.healthStore.write(this.health); throw error }
    while (!signal?.aborted) {
      const attemptedAt = this.clock()
      let waitMilliseconds = this.config.intervalSeconds * 1000
      try {
        await this.collectOnce(attemptedAt)
        this.health = collectionSuccessHealth(this.health, attemptedAt)
      } catch (error) {
        waitMilliseconds = collectionRetryDelay(this.health.consecutiveCollectionFailures + 1, this.config.intervalSeconds)
        this.health = collectionFailureHealth(this.health, attemptedAt, new Date(attemptedAt.valueOf() + waitMilliseconds), error)
      }
      await this.healthStore.write(this.health)
      await this.flush()
      if (!signal?.aborted) await this.delay(waitMilliseconds, signal)
    }
  }
}

export function collectionRetryDelay(failureCount: number, intervalSeconds: number) { return Math.min(intervalSeconds * 1000, 5_000 * 2 ** Math.min(Math.max(failureCount - 1, 0), 6)) }
async function abortableDelay(milliseconds: number, signal?: AbortSignal) { await new Promise<void>((resolve) => { const timer = setTimeout(resolve, milliseconds); signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true }) }) }

export async function createWindowsCollectorRuntime(config: WindowsCollectorConfig) {
  const paths = statePaths(config.stateDirectory); const identity = JSON.parse(await readFile(paths.identity, 'utf8')) as WindowsCollectorIdentity
  const runner = new ConstrainedPowerShellRunner({ scriptsDirectory: config.scriptsDirectory, manifestPath: config.manifestPath, jeaEndpointName: config.executionBoundary.kind === 'JEA' ? config.executionBoundary.endpointName : undefined, allowedScvmmEndpoints: config.scvmm ? [config.scvmm] : [] })
  const spool = new EncryptedWindowsSpool({ directory: config.spoolDirectory, key: Buffer.from((await readFile(paths.spoolKey, 'utf8')).trim(), 'base64'), maxBytes: config.maxSpoolBytes, maxItems: config.maxSpoolItems, acceptedSchemaVersions: [...WINDOWS_ACCEPTED_BUNDLE_SCHEMAS] })
  const signer = new WindowsBundleSigner(await readFile(paths.privateKey, 'utf8'), { orgId: identity.orgId, collectorId: identity.collectorId, signatureKeyId: identity.keyId })
  const proxy = config.upload?.proxy ? { endpoint: config.upload.proxy.endpoint, allowedHosts: config.upload.proxy.allowedHosts, privateAddressAllowedHosts: config.upload.proxy.privateAddressAllowedHosts, authorization: (await readFile(config.upload.proxy.authorizationFile, 'utf8')).trim() } : undefined
  const uploader = config.upload ? new WindowsSpoolUploader(spool, { endpoint: config.upload.endpoint, allowedHosts: config.upload.allowedHosts, privateAddressAllowedHosts: config.upload.privateAddressAllowedHosts, bearerToken: (await readFile(paths.transportToken, 'utf8')).trim(), proxy }) : undefined
  return new WindowsCollectorRuntime(config, runner, spool, signer, identity, uploader)
}
