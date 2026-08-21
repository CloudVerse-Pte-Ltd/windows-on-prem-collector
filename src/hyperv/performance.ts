type JsonMap = Record<string, unknown>
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_ROWS = 1_000_000

export const HYPERV_COUNTER_REGISTRY = Object.freeze({
  'guest.cpu.usage.percent': { unit: 'percent', aggregation: 'GAUGE' },
  'guest.memory.assigned.bytes': { unit: 'bytes', aggregation: 'GAUGE' },
  'guest.storage.read.bytes_per_second': { unit: 'bytes_per_second', aggregation: 'GAUGE' },
  'guest.storage.write.bytes_per_second': { unit: 'bytes_per_second', aggregation: 'GAUGE' },
} as const)
export type HypervCounterKey = keyof typeof HYPERV_COUNTER_REGISTRY

export interface HypervMetricFact { vmUid: string; vmName: string; metricKey: HypervCounterKey; timestamp: string; value: number; unit: string; provenance: { instanceName: string; counterPath: string } }
export interface HypervMetricRollup { vmUid: string; metricKey: HypervCounterKey; sampleCount: number; p95: number; max: number; windowStart: string; windowEnd: string }
export interface HypervMetricGap { code: string; vmUid?: string; metricKey?: string; details?: Record<string, unknown> }

const map = (value: unknown): JsonMap => value && typeof value === 'object' && !Array.isArray(value) ? value as JsonMap : {}
const bounded = (value: unknown, field: string, max = 2048) => { if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`Hyper-V performance ${field} is invalid`); return value.trim() }

function percentile95(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)]!
}

export function normalizeHypervPerformanceOutput(raw: unknown) {
  const root = map(raw)
  if (root.schemaVersion !== '1.0' || root.capability !== 'TELEMETRY' || root.platform !== 'HYPERV' || root.transport !== 'LOCAL_PERFORMANCE_COUNTERS' || root.mutationAttempted !== false) throw new Error('Hyper-V performance output violated the signed contract')
  if (!Array.isArray(root.rows) || root.rows.length > MAX_ROWS || !Array.isArray(root.gaps) || root.gaps.length > MAX_ROWS) throw new Error('Hyper-V performance rows or gaps exceed bounds')
  const facts: HypervMetricFact[] = root.rows.map((candidate, index) => {
    const row = map(candidate); const vmUid = bounded(row.vmUid, `row ${index} vmUid`, 64)
    if (!UUID.test(vmUid)) throw new Error(`Hyper-V performance row ${index} lacks immutable VM GUID`)
    const metricKey = bounded(row.metricKey, `row ${index} metricKey`, 128) as HypervCounterKey
    const registry = HYPERV_COUNTER_REGISTRY[metricKey]
    if (!registry) throw new Error(`Hyper-V performance row ${index} has unknown counter semantic`)
    const timestamp = bounded(row.timestamp, `row ${index} timestamp`, 64); const value = Number(row.value)
    if (!Number.isFinite(Date.parse(timestamp)) || !Number.isFinite(value)) throw new Error(`Hyper-V performance row ${index} has invalid sample`)
    return { vmUid: vmUid.toLowerCase(), vmName: bounded(row.vmName, `row ${index} vmName`), metricKey, timestamp: new Date(timestamp).toISOString(), value, unit: registry.unit,
      provenance: { instanceName: bounded(row.instanceName, `row ${index} instanceName`), counterPath: bounded(row.counterPath, `row ${index} counterPath`, 4096) } }
  })
  const gaps: HypervMetricGap[] = root.gaps.map((candidate, index) => { const gap = map(candidate); return { code: bounded(gap.code, `gap ${index} code`, 128), vmUid: typeof gap.vmUid === 'string' ? gap.vmUid.toLowerCase() : undefined, metricKey: typeof gap.metricKey === 'string' ? gap.metricKey : undefined, details: map(gap.details) } })
  if (!facts.length && !gaps.some((gap) => gap.code === 'NO_LOCAL_HISTORY')) gaps.push({ code: 'NO_LOCAL_HISTORY' })
  const groups = new Map<string, HypervMetricFact[]>()
  for (const fact of facts) { const key = `${fact.vmUid}|${fact.metricKey}`; groups.set(key, [...(groups.get(key) ?? []), fact]) }
  const rollups: HypervMetricRollup[] = [...groups.values()].map((items) => ({ vmUid: items[0]!.vmUid, metricKey: items[0]!.metricKey, sampleCount: items.length,
    p95: percentile95(items.map((item) => item.value)), max: Math.max(...items.map((item) => item.value)),
    windowStart: items.map((item) => item.timestamp).sort()[0]!, windowEnd: items.map((item) => item.timestamp).sort().at(-1)! }))
  return { facts, rollups, gaps, capability: facts.length ? 'READY' as const : 'BLOCKED' as const, history: root.historyAvailable === true ? 'AVAILABLE' as const : 'NO_LOCAL_HISTORY' as const }
}
