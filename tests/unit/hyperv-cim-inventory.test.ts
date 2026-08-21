import { describe, expect, it } from 'vitest'
import { normalizeHypervCimInventory } from '../../src/hyperv/cim-inventory.js'

const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
const context = { collectionRunId: uuid(999), collectedAt: '2026-08-21T00:00:00Z', connectorVersion: '0.1.0' }
const base = { schemaVersion: '1.0', capability: 'INVENTORY', platform: 'HYPERV', transport: 'LOCAL_CIM_V2', mutationAttempted: false,
  host: { UUID: uuid(1), Name: 'hv01', Domain: 'example.com' }, unavailableFamilies: ['SCVMM_HOST_GROUP', 'SCVMM_TEMPLATE', 'SCVMM_STORAGE_FABRIC', 'SCVMM_NETWORK_INTENT'] }

describe('C26 local Hyper-V CIM v2 fallback', () => {
  it('normalizes standalone host/VM/settings and declares reduced coverage explicitly', () => {
    const result = normalizeHypervCimInventory({ ...base, computerSystems: [{ Name: 'hv01', ElementName: 'host' }, { Name: uuid(2), ElementName: 'vm-renamed', EnabledState: 2 }], settings: [{ InstanceID: 'Microsoft:cfg-2', VirtualSystemIdentifier: uuid(2), ElementName: 'cfg', SettingType: 3 }], clusterAvailable: false, clusterNodes: [] }, context)
    expect(result.reducedCoverage).toBe(true)
    expect(result.records.map(({ kind }) => kind)).toEqual(['HOST', 'VIRTUAL_MACHINE', 'VM_CONFIGURATION'])
    expect(result.records[1]).toMatchObject({ sourceUid: uuid(2), relationships: { host: uuid(1) } })
    expect(result.capabilities).toMatchObject({ FAILOVER_CLUSTER: 'UNAVAILABLE', SCVMM_TEMPLATE: 'UNAVAILABLE' })
  })

  it('normalizes failover-cluster membership without using node names as identity', () => {
    const result = normalizeHypervCimInventory({ ...base, computerSystems: [], settings: [], clusterAvailable: true, cluster: { Id: uuid(3), Name: 'cluster-a' }, clusterNodes: [{ Name: 'hv02' }, { Name: 'hv01' }] }, context)
    expect(result.records.at(-1)).toMatchObject({ kind: 'FAILOVER_CLUSTER', sourceUid: uuid(3), relationships: { localHost: uuid(1) }, attributes: { nodeNames: '["hv01","hv02"]' } })
    expect(result.capabilities.FAILOVER_CLUSTER).toBe('READY')
  })

  it('preserves VM identity across rename and rejects malformed identity or hidden coverage', () => {
    const source = (name: string) => ({ ...base, computerSystems: [{ Name: uuid(2), ElementName: name }], settings: [], clusterAvailable: false, clusterNodes: [] })
    expect(normalizeHypervCimInventory(source('old'), context).records[1].sourceUid).toBe(normalizeHypervCimInventory(source('new'), context).records[1].sourceUid)
    expect(() => normalizeHypervCimInventory({ ...source('x'), host: { UUID: 'not-a-uuid', Name: 'hv01' } }, context)).toThrow('immutable UUID')
    expect(() => normalizeHypervCimInventory({ ...source('x'), unavailableFamilies: [] }, context)).toThrow('reduced-coverage')
  })
})
