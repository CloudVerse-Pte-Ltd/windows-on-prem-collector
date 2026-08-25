import { generateKeyPairSync, verify } from 'node:crypto'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { EncryptedWindowsSpool, WindowsSpoolUploader, WINDOWS_ACCEPTED_BUNDLE_SCHEMAS } from '../../src/runtime/encrypted-spool.js'
import { enrollWindowsCollector, statePaths } from '../../src/runtime/enrollment.js'
import { canonicalBundleJson, WindowsBundleSigner } from '../../src/runtime/signed-bundle.js'
import { collectionRetryDelay, collectPerformanceForMode, WindowsCollectorRuntime, type WindowsCollectorConfig } from '../../src/runtime/collector-runtime.js'
import { initialRuntimeHealth, RuntimeHealthStore, type CollectorRuntimeHealth } from '../../src/runtime/runtime-health.js'

describe('Windows collector runtime security', () => {
  it('enrolls with public material and never sends generated secrets', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cv-win-enroll-')); const requests: any[] = []
    const transport = vi.fn(async (url: any, init: any) => { requests.push({ url: String(url), body: JSON.parse(init.body) }); return new Response(null, { status: 201 }) }) as any
    const identity = await enrollWindowsCollector({ controlPlaneUrl: 'https://cpd.example.test/data-center-collector', orgId: 8, integrationId: 21, enrollmentToken: 'bootstrap-secret', stateDirectory: root }, transport)
    const paths = statePaths(root); const privateKey = await readFile(paths.privateKey, 'utf8'); const transportToken = await readFile(paths.transportToken, 'utf8')
    expect(identity.provider).toBe('HYPERV'); expect(requests[0].url).toBe('https://cpd.example.test/data-center-collector/enroll')
    expect(JSON.stringify(requests[0].body)).not.toContain(privateKey); expect(JSON.stringify(requests[0].body)).not.toContain(transportToken)
    expect(requests[0].body.transportTokenHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('reuses one local identity after an ambiguous enrollment failure', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cv-win-enroll-retry-')); const bodies: any[] = []; let attempt = 0
    const transport = vi.fn(async (_url: any, init: any) => { bodies.push(JSON.parse(init.body)); attempt++; if (attempt === 1) throw new Error('connection closed after request'); return new Response(null, { status: 201 }) }) as any
    const config = { controlPlaneUrl: 'https://cpd.example.test/data-center-collector', orgId: 8, integrationId: 22, enrollmentToken: 'bootstrap-secret', stateDirectory: root }
    await expect(enrollWindowsCollector(config, transport)).rejects.toThrow('connection closed')
    const paths = statePaths(root); const firstPrivateKey = await readFile(paths.privateKey, 'utf8'); const pending = JSON.parse(await readFile(paths.pending, 'utf8'))
    const identity = await enrollWindowsCollector(config, transport)
    expect(identity.collectorId).toBe(pending.identity.collectorId); expect(await readFile(paths.privateKey, 'utf8')).toBe(firstPrivateKey)
    expect(bodies[1]).toMatchObject({ collectorId: bodies[0].collectorId, keyId: bodies[0].keyId, publicKeyPem: bodies[0].publicKeyPem, transportTokenHash: bodies[0].transportTokenHash })
    await expect(readFile(paths.pending, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('encrypts spool contents and detects tampering', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-spool-')); const key = Buffer.alloc(32, 7)
    const spool = new EncryptedWindowsSpool({ directory, key, maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
    const queueId = await spool.enqueue('bundle-sensitive', '1.0', Buffer.from('customer-secret-payload'))
    const path = join(directory, `${queueId}.bundle`); const bytes = await readFile(path)
    expect(bytes.toString()).not.toContain('customer-secret-payload'); expect((await spool.list())[0]!.payload.toString()).toBe('customer-secret-payload')
    const envelope = JSON.parse(bytes.toString()); envelope.encrypted = Buffer.from('tampered').toString('base64')
    await import('node:fs/promises').then(({ writeFile }) => writeFile(path, JSON.stringify(envelope)))
    await expect(spool.list()).rejects.toThrow()
  })

  it('signs deterministic canonical bytes with Ed25519', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519'); const signer = new WindowsBundleSigner(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { orgId: 8, collectorId: 'dc-test', signatureKeyId: 'key-test' })
    const bundle = signer.create('018f6e32-4f14-7c1f-aab2-90a7ac957011', { z: 2, a: 1 }, new Date('2026-08-22T00:00:00Z'))
    const { signature, ...unsigned } = bundle
    expect(verify(null, Buffer.from(canonicalBundleJson(unsigned)), publicKey, Buffer.from(signature, 'base64'))).toBe(true)
    expect(canonicalBundleJson({ z: 2, a: 1 })).toBe('{"a":1,"z":2}')
  })

  it('fails closed on insecure enrollment transport', async () => {
    await expect(enrollWindowsCollector({ controlPlaneUrl: 'http://cpd.example.test', orgId: 1, integrationId: 1, enrollmentToken: 'x', stateDirectory: 'unused' })).rejects.toThrow('HTTPS')
  })

  it('keeps SCVMM inventory separate from host-level performance evidence', async () => {
    const runner = { runLocalHypervPerformance: vi.fn() } as any
    const result = await collectPerformanceForMode('SCVMM', runner)
    expect(runner.runLocalHypervPerformance).not.toHaveBeenCalled()
    expect(result.facts).toEqual([])
    expect(result.gaps).toEqual([expect.objectContaining({ code: 'HOST_LEVEL_PERFORMANCE_COLLECTOR_REQUIRED', details: expect.objectContaining({ localHostCountersRejected: true }) })])
  })

  it('persists a redacted collection gap, retries, and recovers without emitting a failed-cycle bundle', async () => {
    const config: WindowsCollectorConfig = { stateDirectory: 'state', spoolDirectory: 'spool', scriptsDirectory: 'scripts', manifestPath: 'manifest', managementPlaneUid: 'hyperv:018f6e32-4f14-7c1f-aab2-90a7ac957011', mode: 'LOCAL_HYPERV', scaleClass: 'S', executionBoundary: { kind: 'JEA', endpointName: 'CloudVerseCollector' }, intervalSeconds: 60, maxSpoolBytes: 1_000_000, maxSpoolItems: 10, offlineExportDirectory: 'export' }
    const runner = { initialize: vi.fn(async () => undefined) } as any
    const writes: CollectorRuntimeHealth[] = []; const healthStore = { path: 'health', read: vi.fn(async () => undefined), write: vi.fn(async (health: CollectorRuntimeHealth) => { writes.push(structuredClone(health)) }) } as any
    const controller = new AbortController(); let delays = 0
    const runtime = new WindowsCollectorRuntime(config, runner, { acceptedSchemas: () => ['1.0', '0.9'] } as any, {} as any, {} as any, undefined, healthStore, () => new Date('2026-08-22T03:00:00Z'), async () => { if (++delays === 2) controller.abort() })
    const collect = vi.spyOn(runtime, 'collectOnce').mockRejectedValueOnce(new Error('token=customer-secret connection failed')).mockResolvedValueOnce({ collectionRunId: '018f6e32-4f14-7c1f-aab2-90a7ac957012', bundleId: 'bundle' })
    const flush = vi.spyOn(runtime, 'flush').mockResolvedValue({ sent: 0 })
    await runtime.run(controller.signal)
    expect(collect).toHaveBeenCalledTimes(2); expect(flush).toHaveBeenCalledTimes(2)
    expect(writes[1]).toMatchObject({ status: 'DEGRADED', consecutiveCollectionFailures: 1, collectionGapStartedAt: '2026-08-22T03:00:00.000Z' })
    expect(writes[1]!.lastError).toBe('token=[REDACTED] connection failed')
    expect(writes[2]).toMatchObject({ status: 'HEALTHY', consecutiveCollectionFailures: 0, collectionGapStartedAt: null, lastError: null,
      lastRecoveredCollectionGap: { startedAt: '2026-08-22T03:00:00.000Z', recoveredAt: '2026-08-22T03:00:00.000Z', failedAttempts: 1 } })
  })

  it('bounds collection retry backoff by the configured collection interval', () => {
    expect(collectionRetryDelay(1, 300)).toBe(5_000)
    expect(collectionRetryDelay(4, 300)).toBe(40_000)
    expect(collectionRetryDelay(20, 60)).toBe(60_000)
  })

  it('validates the signed execution boundary and reports upgrade compatibility without collecting', async () => {
    const runner = { initialize: vi.fn(async () => undefined) } as any; const collect = vi.fn()
    const runtime = new WindowsCollectorRuntime({ stateDirectory: 'state', spoolDirectory: 'spool', scriptsDirectory: 'scripts', manifestPath: 'manifest', managementPlaneUid: 'hyperv:018f6e32-4f14-7c1f-aab2-90a7ac957011', mode: 'LOCAL_HYPERV', scaleClass: 'S', executionBoundary: { kind: 'JEA', endpointName: 'CloudVerseCollector' }, intervalSeconds: 60, maxSpoolBytes: 1_000_000, maxSpoolItems: 10, offlineExportDirectory: 'export' }, runner, { acceptedSchemas: () => ['1.0', '0.9'], enqueue: collect } as any, {} as any, {} as any)
    await expect(runtime.validate()).resolves.toEqual({ valid: true, mode: 'LOCAL_HYPERV', managementPlaneUid: 'hyperv:018f6e32-4f14-7c1f-aab2-90a7ac957011', acceptedBundleSchemas: ['1.0', '0.9'] })
    expect(runner.initialize).toHaveBeenCalledOnce(); expect(collect).not.toHaveBeenCalled()
  })

  it('atomically persists and reloads runtime health across process restarts', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-health-')); const store = new RuntimeHealthStore(directory)
    const health = initialRuntimeHealth(new Date('2026-08-22T03:00:00Z')); health.status = 'DEGRADED'; health.consecutiveCollectionFailures = 2
    await store.write(health)
    await expect(store.read()).resolves.toEqual(health)
    expect((await import('node:fs/promises').then(({ readdir }) => readdir(directory))).filter((name) => name.endsWith('.tmp'))).toEqual([])
  })

  it('retains encrypted bundles across DNS failure and recovers without restart', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-outage-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 9), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
    await spool.enqueue('bundle-outage', '1.0', Buffer.from('signed-envelope'))
    let available = false
    const resolver = vi.fn(async () => { if (!available) throw new Error('lookup token=secret failed'); return ['8.8.8.8'] })
    const sender = vi.fn(async () => new Response(null, { status: 202 })) as any
    const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test/bundles', allowedHosts: ['ingest.example.test'], bearerToken: 'transport-secret' }, resolver, sender)
    const started = new Date(Date.now() + 1_000)
    await expect(uploader.flushOnce(started)).resolves.toMatchObject({ sent: 0, deferred: 1 })
    expect(await spool.usage()).toMatchObject({ items: 1 }); expect((await uploader.health()).lastError).not.toContain('secret')
    available = true
    await expect(uploader.flushOnce(new Date(started.valueOf() + 2_000))).resolves.toMatchObject({ sent: 1 })
    expect(await spool.usage()).toMatchObject({ items: 0 }); expect(await uploader.health()).toMatchObject({ healthy: true, lastError: null })
  })

  it('creates a CPD collection run through the fixed authenticated route before direct push', async () => {
    const requests: Array<{ url: string; body: any; headers: any }> = []
    const sender = vi.fn(async (url: any, init: any) => {
      requests.push({ url: String(url), body: JSON.parse(init.body), headers: init.headers })
      return new Response(JSON.stringify({ id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', managementPlaneUid: 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }), { status: 201, headers: { 'content-type': 'application/json' } })
    }) as any
    const uploader = new WindowsSpoolUploader({} as any, { endpoint: 'https://test.cloudverse.ai/api-gw/data-center-collector/bundles/push', allowedHosts: ['test.cloudverse.ai'], bearerToken: 'transport-secret' }, async () => ['8.8.8.8'], sender)
    const input = { orgId: 3, integrationId: 3007, collectorId: 'dc-test', signatureKeyId: 'key-test', managementPlaneUid: 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', adapterName: 'cloudverse-windows-collector', adapterVersion: '0.1.0', scaleClass: 'S' as const }
    await expect(uploader.startRun(input)).resolves.toBe('cccccccc-cccc-4ccc-8ccc-cccccccccccc')
    expect(requests).toEqual([{ url: 'https://test.cloudverse.ai/api-gw/data-center-collector/runs/start', body: input, headers: { 'content-type': 'application/json', authorization: 'Bearer transport-secret' } }])
  })

  it('fails closed on noncanonical, private, or scope-mismatched collector run assignments', async () => {
    const input = { orgId: 3, integrationId: 3007, collectorId: 'dc-test', signatureKeyId: 'key-test', managementPlaneUid: 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', adapterName: 'cloudverse-windows-collector', adapterVersion: '0.1.0', scaleClass: 'S' as const }
    const noncanonical = new WindowsSpoolUploader({} as any, { endpoint: 'https://test.cloudverse.ai/arbitrary', allowedHosts: ['test.cloudverse.ai'], bearerToken: 'token' }, async () => ['8.8.8.8'], vi.fn() as any)
    await expect(noncanonical.startRun(input)).rejects.toThrow('fixed collector run endpoint')
    const privateTarget = new WindowsSpoolUploader({} as any, { endpoint: 'https://test.cloudverse.ai/data-center-collector/bundles/push', allowedHosts: ['test.cloudverse.ai'], bearerToken: 'token' }, async () => ['10.0.0.8'], vi.fn() as any)
    await expect(privateTarget.startRun(input)).rejects.toThrow('prohibited address')
    const mismatch = new WindowsSpoolUploader({} as any, { endpoint: 'https://test.cloudverse.ai/data-center-collector/bundles/push', allowedHosts: ['test.cloudverse.ai'], bearerToken: 'token' }, async () => ['8.8.8.8'], vi.fn(async () => new Response(JSON.stringify({ id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', managementPlaneUid: 'scvmm:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }), { status: 201, headers: { 'content-type': 'application/json' } })) as any)
    await expect(mismatch.startRun(input)).rejects.toThrow('assignment response is invalid')
  })

  it('delivers N-1 queued bytes unchanged and preserves older incompatible schemas for rollback', async () => {
    expect(WINDOWS_ACCEPTED_BUNDLE_SCHEMAS).toEqual(['1.0', '0.9'])
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-upgrade-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 6), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: [...WINDOWS_ACCEPTED_BUNDLE_SCHEMAS] })
    const previousBytes = Buffer.from('{"schemaVersion":"0.9","signed":"previous-release-bytes"}')
    await spool.enqueue('bundle-n-minus-one', '0.9', previousBytes); await spool.enqueue('bundle-too-old', '0.8', Buffer.from('preserve-for-rollback'))
    const sent: Array<{ schema: string; body: Buffer }> = []
    const sender = vi.fn(async (_url: any, init: any) => { sent.push({ schema: init.headers['x-bundle-schema-version'], body: Buffer.from(init.body) }); return new Response(null, { status: 202 }) }) as any
    const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test', allowedHosts: ['ingest.example.test'], bearerToken: 'transport-token' }, async () => ['8.8.8.8'], sender)
    await expect(uploader.flushOnce(new Date(Date.now() + 1_000))).resolves.toMatchObject({ sent: 1, incompatible: 1 })
    expect(sent).toEqual([{ schema: '0.9', body: previousBytes }]); expect(await spool.usage()).toMatchObject({ items: 1 })
    await expect(uploader.health()).resolves.toMatchObject({ healthy: false, incompatible: 1, incompatibleSchemas: ['0.8'], acceptedSchemas: ['1.0', '0.9'] })
  })

  it('uses an allowlisted authenticated HTTPS proxy without exposing its authorization', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-proxy-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 4), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
    await spool.enqueue('bundle-proxy', '1.0', Buffer.from('signed-envelope'))
    const resolver = vi.fn(async (hostname: string) => hostname === 'proxy.example.test' ? ['8.8.4.4'] : ['8.8.8.8'])
    const sender = vi.fn(async (_url: any, init: any) => { expect(init.dispatcher).toBeDefined(); expect(JSON.stringify(init.headers)).not.toContain('proxy-secret'); return new Response(null, { status: 202 }) }) as any
    const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test/bundles', allowedHosts: ['ingest.example.test'], bearerToken: 'transport-token', proxy: { endpoint: 'https://proxy.example.test:8443', allowedHosts: ['proxy.example.test'], authorization: 'Bearer proxy-secret' } }, resolver, sender)
    await expect(uploader.flushOnce(new Date(Date.now() + 1_000))).resolves.toMatchObject({ sent: 1, deferred: 0 })
    expect(resolver).toHaveBeenCalledWith('ingest.example.test'); expect(resolver).toHaveBeenCalledWith('proxy.example.test')
  })

  it('defers bundles when an authenticated proxy resolves outside its approved address policy', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-proxy-denied-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 3), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
    await spool.enqueue('bundle-proxy-denied', '1.0', Buffer.from('signed-envelope'))
    const sender = vi.fn() as any
    const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test', allowedHosts: ['ingest.example.test'], bearerToken: 'transport-token', proxy: { endpoint: 'https://proxy.example.test', allowedHosts: ['proxy.example.test'], authorization: 'Basic cHJveHktc2VjcmV0' } }, async (hostname) => hostname === 'proxy.example.test' ? ['10.0.0.8'] : ['8.8.8.8'], sender)
    await expect(uploader.flushOnce(new Date(Date.now() + 1_000))).resolves.toMatchObject({ sent: 0, deferred: 1 })
    expect(sender).not.toHaveBeenCalled(); expect(await spool.usage()).toMatchObject({ items: 1 })
  })

  it.each(['10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.1.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '2001:db8::1', '::ffff:127.0.0.1'])(
    'rejects prohibited upload address %s without losing the bundle', async (address) => {
      const directory = await mkdtemp(join(tmpdir(), 'cv-win-ssrf-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 5), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
      await spool.enqueue(`bundle-${address}`, '1.0', Buffer.from('payload'))
      const sender = vi.fn() as any; const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test', allowedHosts: ['ingest.example.test'], bearerToken: 'token' }, async () => [address], sender)
      await expect(uploader.flushOnce(new Date('2026-08-22T00:00:00Z'))).resolves.toMatchObject({ sent: 0, deferred: 1 })
      expect(sender).not.toHaveBeenCalled(); expect(await spool.usage()).toMatchObject({ items: 1 })
    },
  )
})
