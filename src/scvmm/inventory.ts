import { ScvmmDiscoveryContext } from './discovery.js'
import { ScvmmDiscoveryParameters, validateScvmmDiscoveryParameters } from '../security/command-catalog.js'
import { ConstrainedPowerShellRunner } from '../security/powershell-runner.js'

export type ScvmmAssetKind = 'HOST_GROUP' | 'CLUSTER' | 'HOST' | 'VIRTUAL_MACHINE' | 'TEMPLATE' | 'CHECKPOINT' | 'STORAGE_ARRAY' | 'STORAGE_POOL' | 'LOGICAL_NETWORK' | 'VM_NETWORK'
export interface ScvmmInventoryAsset {
  kind: ScvmmAssetKind
  sourceUid: string
  name: string
  attributes: Record<string, string | number | boolean | null>
  relationships: Record<string, string>
}
export interface ScvmmInventoryResult {
  records: ScvmmInventoryAsset[]
  page: { receivedCount: number; complete: true }
  errors: []
  provenance: { connectorId: 'cloudverse.hyperv.scvmm'; connectorVersion: string; collectionRunId: string; collectedAt: string; source: { endpoint: string; queryId: 'scvmm.inventory.v1' } }
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const ZERO_GUID = /^0{8}-0{4}-0{4}-0{4}-0{12}$/i
const MAX_PER_FAMILY = 100_000
const families: Array<[string, ScvmmAssetKind]> = [
  ['hostGroups', 'HOST_GROUP'], ['clusters', 'CLUSTER'], ['hosts', 'HOST'], ['virtualMachines', 'VIRTUAL_MACHINE'], ['templates', 'TEMPLATE'],
  ['checkpoints', 'CHECKPOINT'], ['storageArrays', 'STORAGE_ARRAY'], ['storagePools', 'STORAGE_POOL'], ['logicalNetworks', 'LOGICAL_NETWORK'], ['vmNetworks', 'VM_NETWORK'],
]
const relationFields = new Set(['ParentHostGroup', 'VMHostGroup', 'HostGroup', 'HostCluster', 'VMHost', 'VM', 'StorageArray', 'LogicalNetwork'])

function text(value: unknown, field: string, max = 2048) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`SCVMM inventory ${field} is invalid`)
  return value.trim()
}
function uid(value: unknown, field: string) {
  const candidate = typeof value === 'string' ? value : value && typeof value === 'object' ? String((value as Record<string, unknown>).ID ?? '') : ''
  if (!GUID.test(candidate) || ZERO_GUID.test(candidate)) throw new Error(`SCVMM inventory ${field} lacks an immutable GUID`)
  return candidate.toLowerCase()
}
function scalar(value: unknown): string | number | boolean | null | undefined {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (value instanceof Date) return value.toISOString()
  return undefined
}

export function normalizeScvmmInventoryOutput(raw: unknown, parameters: ScvmmDiscoveryParameters, context: ScvmmDiscoveryContext): ScvmmInventoryResult {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('SCVMM inventory output must be an object')
  const root = raw as Record<string, unknown>
  if (root.schemaVersion !== '1.0' || root.capability !== 'INVENTORY' || root.platform !== 'HYPERV' || root.mutationAttempted !== false) throw new Error('SCVMM inventory output violated the signed contract')
  if (!UUID.test(context.collectionRunId) || Number.isNaN(Date.parse(context.collectedAt)) || !context.connectorVersion) throw new Error('SCVMM inventory context is invalid')
  const records: ScvmmInventoryAsset[] = []
  const seen = new Set<string>()
  for (const [family, kind] of families) {
    const items = root[family] ?? []
    if (!Array.isArray(items) || items.length > MAX_PER_FAMILY) throw new Error(`SCVMM inventory ${family} is invalid or exceeds the scale bound`)
    for (const candidate of items) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) throw new Error(`SCVMM inventory ${family} row is invalid`)
      const item = candidate as Record<string, unknown>; const sourceUid = uid(item.ID ?? item.id, `${family}.ID`)
      const key = `${kind}:${sourceUid}`; if (seen.has(key)) throw new Error(`SCVMM inventory contains duplicate immutable identity ${key}`); seen.add(key)
      const attributes: ScvmmInventoryAsset['attributes'] = {}; const relationships: Record<string, string> = {}
      for (const [field, value] of Object.entries(item)) {
        if (/^(ID|Name)$/i.test(field)) continue
        if (relationFields.has(field) && value != null) relationships[field] = uid(value, `${family}.${field}`)
        else { const normalized = scalar(value); if (normalized !== undefined) attributes[field] = normalized }
      }
      records.push({ kind, sourceUid, name: text(item.Name ?? item.name, `${family}.Name`, 253), attributes, relationships })
    }
  }
  const endpoint = `${parameters.server.toLowerCase()}:${parameters.port}`
  return { records, errors: [], page: { receivedCount: records.length, complete: true }, provenance: { connectorId: 'cloudverse.hyperv.scvmm', connectorVersion: context.connectorVersion, collectionRunId: context.collectionRunId, collectedAt: new Date(context.collectedAt).toISOString(), source: { endpoint: `scvmm://${endpoint}`, queryId: 'scvmm.inventory.v1' } } }
}

export class ScvmmInventoryAdapter {
  constructor(private readonly runner: ConstrainedPowerShellRunner) {}
  async collect(parameters: unknown, context: ScvmmDiscoveryContext) {
    const approved = validateScvmmDiscoveryParameters(parameters)
    return normalizeScvmmInventoryOutput(await this.runner.runScvmmInventory(approved), approved, context)
  }
}
