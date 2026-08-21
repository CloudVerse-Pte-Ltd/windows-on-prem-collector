import type { HypervCimInventoryResult } from './cim-inventory.js'
import type { ScvmmInventoryResult } from '../scvmm/inventory.js'

export interface HypervInventoryEnvelope {
  type: 'HYPER_V_INVENTORY'
  integrationId: number
  managementPlaneUid: string
  collectedAt: string
  transport: 'SCVMM_POWERSHELL' | 'LOCAL_CIM_V2'
  reducedCoverage: boolean
  records: Array<{ kind: string; sourceUid: string; name: string; attributes: Record<string, unknown>; relationships: Record<string, string> }>
}

const SCVMM_UID = /^scvmm:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function toHypervInventoryEnvelope(
  integrationId: number,
  managementPlaneUid: string,
  inventory: ScvmmInventoryResult | HypervCimInventoryResult,
): HypervInventoryEnvelope {
  if (!Number.isSafeInteger(integrationId) || integrationId <= 0) throw new Error('Hyper-V envelope integrationId is invalid')
  if (!SCVMM_UID.test(managementPlaneUid)) throw new Error('Hyper-V envelope requires immutable SCVMM UUID')
  if (!inventory.page.complete || inventory.page.receivedCount !== inventory.records.length || inventory.errors.length) throw new Error('Hyper-V inventory is incomplete')
  if (!Number.isFinite(Date.parse(inventory.provenance.collectedAt))) throw new Error('Hyper-V inventory collectedAt is invalid')
  const cim = 'reducedCoverage' in inventory
  return {
    type: 'HYPER_V_INVENTORY', integrationId, managementPlaneUid,
    collectedAt: new Date(inventory.provenance.collectedAt).toISOString(),
    transport: cim ? 'LOCAL_CIM_V2' : 'SCVMM_POWERSHELL',
    reducedCoverage: cim,
    records: inventory.records,
  }
}
