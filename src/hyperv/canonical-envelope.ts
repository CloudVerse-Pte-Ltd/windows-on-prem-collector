import type { HypervCimInventoryResult } from './cim-inventory.js'
import type { ScvmmInventoryResult } from '../scvmm/inventory.js'
import type { HypervMetricGap, HypervMetricFact } from './performance.js'

export interface HypervInventoryEnvelope {
  type: 'HYPER_V_INVENTORY'
  integrationId: number
  managementPlaneUid: string
  collectedAt: string
  transport: 'SCVMM_POWERSHELL' | 'LOCAL_CIM_V2'
  reducedCoverage: boolean
  records: Array<{ kind: string; sourceUid: string; name: string; attributes: Record<string, unknown>; relationships: Record<string, string> }>
}

const PLANE_UID = /^(?:scvmm|hyperv):[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const NATIVE_METRIC: Record<string, string> = {
  'guest.cpu.usage.percent': 'hyperv.virtual_processor.total_run_time',
  'guest.memory.assigned.bytes': 'hyperv.dynamic_memory.physical_memory',
  'guest.storage.read.bytes_per_second': 'hyperv.virtual_storage.read_bytes_per_second',
  'guest.storage.write.bytes_per_second': 'hyperv.virtual_storage.write_bytes_per_second',
}

export function toHypervInventoryEnvelope(
  integrationId: number,
  managementPlaneUid: string,
  inventory: ScvmmInventoryResult | HypervCimInventoryResult,
): HypervInventoryEnvelope {
  if (!Number.isSafeInteger(integrationId) || integrationId <= 0) throw new Error('Hyper-V envelope integrationId is invalid')
  const cim = 'reducedCoverage' in inventory
  const expectedPrefix = cim ? 'hyperv:' : 'scvmm:'
  if (!PLANE_UID.test(managementPlaneUid) || !managementPlaneUid.toLowerCase().startsWith(expectedPrefix)) throw new Error(`Hyper-V envelope requires immutable ${cim ? 'host' : 'SCVMM'} UUID`)
  if (!inventory.page.complete || inventory.page.receivedCount !== inventory.records.length || inventory.errors.length) throw new Error('Hyper-V inventory is incomplete')
  if (!Number.isFinite(Date.parse(inventory.provenance.collectedAt))) throw new Error('Hyper-V inventory collectedAt is invalid')
  return {
    type: 'HYPER_V_INVENTORY', integrationId, managementPlaneUid,
    collectedAt: new Date(inventory.provenance.collectedAt).toISOString(),
    transport: cim ? 'LOCAL_CIM_V2' : 'SCVMM_POWERSHELL',
    reducedCoverage: cim,
    records: inventory.records,
  }
}

export interface HypervTelemetryEnvelope {
  type: 'DATA_CENTER_METRICS'
  integrationId: number
  managementPlaneUid: string
  collectedAt: string
  platform: 'HYPERV'
  metricSet: 'hyperv.vm.performance'
  metrics: Array<{ assetKind: 'VIRTUAL_MACHINE'; sourceUid: string; semanticMetric: string; nativeMetric: string; observedAt: string; intervalSeconds: number; value: string; unit: string; aggregation: 'AVERAGE'; retentionClass: 'TELEMETRY'; retentionDays: 90; provenance: Record<string, unknown> }>
  gaps: Array<{ assetKind?: 'VIRTUAL_MACHINE'; sourceUid?: string; semanticMetric: string; expectedStart: string; expectedEnd: string; reasonClass: string; retryable: boolean; state: 'OPEN'; evidence: Record<string, unknown> }>
}

export interface HypervCollectionPayload {
  records: [HypervInventoryEnvelope, HypervTelemetryEnvelope]
  completion: {
    status: 'SUCCEEDED' | 'PARTIAL'
    recordCounts: { assets: number; metrics: number; gaps: number; errors: number }
    coverage: { inventory: 'COMPLETE'; telemetry: 'COMPLETE' | 'PARTIAL'; reducedCoverage: boolean }
    errors: Array<Record<string, unknown>>
  }
}

export function toHypervTelemetryEnvelope(integrationId: number, managementPlaneUid: string, collectedAt: string, facts: HypervMetricFact[], gaps: HypervMetricGap[]): HypervTelemetryEnvelope {
  if (!Number.isSafeInteger(integrationId) || integrationId <= 0 || !PLANE_UID.test(managementPlaneUid)) throw new Error('Hyper-V telemetry scope is invalid')
  const end = new Date(collectedAt); if (!Number.isFinite(end.getTime())) throw new Error('Hyper-V telemetry collectedAt is invalid')
  const start = new Date(end.getTime() - 1000)
  return {
    type: 'DATA_CENTER_METRICS', integrationId, managementPlaneUid, collectedAt: end.toISOString(), platform: 'HYPERV', metricSet: 'hyperv.vm.performance',
    metrics: facts.map((fact) => ({
      assetKind: 'VIRTUAL_MACHINE', sourceUid: fact.vmUid, semanticMetric: fact.metricKey,
      nativeMetric: NATIVE_METRIC[fact.metricKey]!, observedAt: fact.timestamp, intervalSeconds: 1,
      value: String(fact.value), unit: fact.unit, aggregation: 'AVERAGE', retentionClass: 'TELEMETRY', retentionDays: 90,
      provenance: { vmName: fact.vmName, ...fact.provenance },
    })),
    gaps: gaps.map((gap) => ({
      ...(gap.vmUid ? { assetKind: 'VIRTUAL_MACHINE' as const, sourceUid: gap.vmUid } : {}), semanticMetric: gap.metricKey || 'hyperv.vm.performance',
      expectedStart: start.toISOString(), expectedEnd: end.toISOString(), reasonClass: gap.code,
      retryable: gap.code !== 'NO_LOCAL_HISTORY', state: 'OPEN', evidence: gap.details || {},
    })),
  }
}

export function toHypervCollectionPayload(inventory: HypervInventoryEnvelope, telemetry: HypervTelemetryEnvelope): HypervCollectionPayload {
  if (inventory.integrationId !== telemetry.integrationId || inventory.managementPlaneUid.toLowerCase() !== telemetry.managementPlaneUid.toLowerCase()) throw new Error('Hyper-V inventory and telemetry scope must match')
  const errors = telemetry.gaps.map((gap) => ({ code: gap.reasonClass, semanticMetric: gap.semanticMetric, retryable: gap.retryable }))
  return {
    records: [inventory, telemetry],
    completion: {
      status: telemetry.gaps.length ? 'PARTIAL' : 'SUCCEEDED',
      recordCounts: { assets: inventory.records.length, metrics: telemetry.metrics.length, gaps: telemetry.gaps.length, errors: errors.length },
      coverage: { inventory: 'COMPLETE', telemetry: telemetry.gaps.length ? 'PARTIAL' : 'COMPLETE', reducedCoverage: inventory.reducedCoverage },
      errors,
    },
  }
}
