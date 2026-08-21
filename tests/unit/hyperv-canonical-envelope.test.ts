import { describe, expect, it } from 'vitest'
import { toHypervInventoryEnvelope } from '../../src/index.js'

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
})
