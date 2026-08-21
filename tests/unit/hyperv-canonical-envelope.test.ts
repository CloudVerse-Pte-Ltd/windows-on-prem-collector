import { describe, expect, it } from 'vitest'
import { toHypervInventoryEnvelope, toHypervTelemetryEnvelope } from '../../src/index.js'

const inventory = {
  records: [{ kind: 'VIRTUAL_MACHINE' as const, sourceUid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', name: 'vm01', attributes: {}, relationships: {} }],
  errors: [] as [], page: { receivedCount: 1, complete: true as const },
  provenance: { connectorId: 'cloudverse.hyperv.scvmm' as const, connectorVersion: '1.0.0', collectionRunId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', collectedAt: '2026-08-21T00:00:00Z', source: { endpoint: 'scvmm://internal:8100', queryId: 'scvmm.inventory.v1' as const } },
}

describe('C27 Hyper-V canonical envelope', () => {
  it('preserves immutable identities and inventory without synthetic fallbacks', () => {
    expect(toHypervInventoryEnvelope(7, 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', inventory)).toEqual(expect.objectContaining({
      type: 'HYPER_V_INVENTORY', integrationId: 7, managementPlaneUid: 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      transport: 'SCVMM_POWERSHELL', reducedCoverage: false, records: inventory.records,
    }))
  })

  it('fails closed on endpoint identity or incomplete inventory', () => {
    expect(() => toHypervInventoryEnvelope(7, 'vmm01:8100', inventory)).toThrow('immutable SCVMM')
    expect(() => toHypervInventoryEnvelope(7, 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', { ...inventory, page: { receivedCount: 0, complete: true } })).toThrow('incomplete')
  })

  it('uses the host firmware UUID for standalone CIM and creates canonical telemetry inputs', () => {
    const cim = { ...inventory, reducedCoverage: true as const, capabilities: {}, provenance: { connectorId: 'cloudverse.hyperv.cim-v2' as const, connectorVersion: '0.1.0', collectionRunId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', collectedAt: '2026-08-21T00:00:00Z', transport: 'LOCAL_CIM_V2' as const } }
    expect(toHypervInventoryEnvelope(7, 'hyperv:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', cim)).toMatchObject({ transport: 'LOCAL_CIM_V2', reducedCoverage: true })
    expect(() => toHypervInventoryEnvelope(7, 'scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', cim)).toThrow('immutable host')
    const telemetry = toHypervTelemetryEnvelope(7, 'hyperv:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '2026-08-21T00:00:01Z', [{
      vmUid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', vmName: 'renamed', metricKey: 'guest.memory.assigned.bytes', timestamp: '2026-08-21T00:00:01Z', value: 536870912, unit: 'bytes', provenance: { instanceName: 'renamed', counterPath: '\\counter' },
    }], [])
    expect(telemetry.metrics[0]).toMatchObject({ sourceUid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', nativeMetric: 'hyperv.dynamic_memory.physical_memory', value: '536870912', retentionDays: 90 })
  })
})
