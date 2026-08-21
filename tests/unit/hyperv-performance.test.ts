import { describe, expect, it } from 'vitest'
import { normalizeHypervPerformanceOutput } from '../../src/index.js'

const vmUid = '11111111-1111-4111-8111-111111111111'
const raw = (rows: unknown[], gaps: unknown[] = []) => ({ schemaVersion: '1.0', capability: 'TELEMETRY', platform: 'HYPERV', transport: 'LOCAL_PERFORMANCE_COUNTERS', historyAvailable: false, mutationAttempted: false, rows, gaps })
const sample = (vmName: string, value: number, timestamp: string) => ({ vmUid, vmName, metricKey: 'guest.cpu.usage.percent', timestamp, value, instanceName: `${vmName}:Hv VP 0`, counterPath: String.raw`\\host\Hyper-V Hypervisor Virtual Processor(instance)\% Guest Run Time` })

describe('C32 Hyper-V performance normalization', () => {
  it('maps metrics to immutable VM GUIDs and computes deterministic p95/max rollups', () => {
    const result = normalizeHypervPerformanceOutput(raw([
      sample('finance-old', 10, '2026-08-21T00:00:00Z'), sample('finance-new', 50, '2026-08-21T00:01:00Z'), sample('finance-new', 90, '2026-08-21T00:02:00Z'),
    ]))
    expect(new Set(result.facts.map((fact) => fact.vmUid))).toEqual(new Set([vmUid]))
    expect(result.facts.map((fact) => fact.vmName)).toEqual(['finance-old', 'finance-new', 'finance-new'])
    expect(result.rollups).toEqual([expect.objectContaining({ vmUid, metricKey: 'guest.cpu.usage.percent', sampleCount: 3, p95: 90, max: 90 })])
    expect(result.history).toBe('NO_LOCAL_HISTORY')
  })

  it('retains restart/unresolved-instance gaps without inventing VM identity', () => {
    const result = normalizeHypervPerformanceOutput(raw([], [{ code: 'COUNTER_INSTANCE_VM_GUID_UNRESOLVED', metricKey: 'guest.cpu.usage.percent', details: { instanceName: 'renamed-vm', matchCount: 0 } }]))
    expect(result.facts).toEqual([])
    expect(result.gaps[0]).toMatchObject({ code: 'COUNTER_INSTANCE_VM_GUID_UNRESOLVED', metricKey: 'guest.cpu.usage.percent' })
    expect(result.capability).toBe('BLOCKED')
  })

  it('states no local history explicitly and fails closed on unknown counters or mutable identity', () => {
    expect(normalizeHypervPerformanceOutput(raw([], [])).gaps).toContainEqual({ code: 'NO_LOCAL_HISTORY' })
    expect(() => normalizeHypervPerformanceOutput(raw([{ ...sample('vm', 1, '2026-08-21T00:00:00Z'), metricKey: 'synthetic.cpu' }]))).toThrow('unknown counter')
    expect(() => normalizeHypervPerformanceOutput(raw([{ ...sample('vm', 1, '2026-08-21T00:00:00Z'), vmUid: 'vm-name' }]))).toThrow('immutable VM GUID')
  })
})
