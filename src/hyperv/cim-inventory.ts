import { createHash } from 'node:crypto'
import { ConstrainedPowerShellRunner } from '../security/powershell-runner.js'
import { ScvmmDiscoveryContext } from '../scvmm/discovery.js'

export type HypervCimAssetKind = 'HOST' | 'VIRTUAL_MACHINE' | 'VM_CONFIGURATION' | 'CHECKPOINT' | 'FAILOVER_CLUSTER'
export interface HypervCimAsset { kind: HypervCimAssetKind; sourceUid: string; name: string; attributes: Record<string, string | number | boolean | null>; relationships: Record<string, string> }
export interface HypervCimInventoryResult {
  records: HypervCimAsset[]
  errors: []
  page: { receivedCount: number; complete: true }
  reducedCoverage: true
  capabilities: Record<string, 'READY' | 'UNAVAILABLE'>
  provenance: { connectorId: 'cloudverse.hyperv.cim-v2'; connectorVersion: string; collectionRunId: string; collectedAt: string; transport: 'LOCAL_CIM_V2' }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_ITEMS = 100_000
const requiredUnavailable = ['SCVMM_HOST_GROUP', 'SCVMM_TEMPLATE', 'SCVMM_STORAGE_FABRIC', 'SCVMM_NETWORK_INTENT']
const normalizeUuid = (value: unknown, field: string) => {
  const candidate = String(value ?? '').trim()
  if (!UUID.test(candidate) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/i.test(candidate)) throw new Error(`Hyper-V CIM ${field} lacks an immutable UUID`)
  return candidate.toLowerCase()
}
const string = (value: unknown, field: string, max = 2048) => {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`Hyper-V CIM ${field} is invalid`)
  return value.trim()
}
const rows = (value: unknown, field: string) => {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) throw new Error(`Hyper-V CIM ${field} is invalid or exceeds the scale bound`)
  return value as Array<Record<string, unknown>>
}
const scalars = (record: Record<string, unknown>, omitted: Set<string>) => Object.fromEntries(Object.entries(record).flatMap(([key, value]) => {
  if (omitted.has(key)) return []
  return value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value)) ? [[key, value]] : []
})) as HypervCimAsset['attributes']
const uuidFromInstanceId = (value: unknown, field: string) => {
  const candidate = string(value, field, 2048)
  const match = candidate.match(/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i)
  return match ? match[0]!.toLowerCase() : null
}
const keyedSettings = (value: unknown, field: string, allowedVmUids: Set<string>) => {
  const result = new Map<string, Record<string, unknown>>()
  for (const row of rows(value ?? [], field)) {
    const vmUid = uuidFromInstanceId(row.InstanceID, `${field}.InstanceID`)
    if (!vmUid || !allowedVmUids.has(vmUid)) continue
    if (result.has(vmUid)) throw new Error(`Hyper-V CIM ${field} contains ambiguous settings for VM ${vmUid}`)
    result.set(vmUid, row)
  }
  return result
}
const memoryBytes = (row: Record<string, unknown>) => {
  const quantity = Number(row.VirtualQuantity); const units = String(row.AllocationUnits ?? '').trim().toLowerCase()
  const multiplier: Record<string, number> = { byte: 1, 'byte * 2^10': 2 ** 10, 'byte * 2^20': 2 ** 20, 'byte * 2^30': 2 ** 30 }
  if (!Number.isSafeInteger(quantity) || quantity <= 0 || !multiplier[units]) throw new Error('Hyper-V CIM memory allocation has invalid quantity or units')
  return quantity * multiplier[units]!
}

export function normalizeHypervCimInventory(raw: unknown, context: ScvmmDiscoveryContext): HypervCimInventoryResult {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Hyper-V CIM inventory output must be an object')
  const root = raw as Record<string, unknown>
  if (root.schemaVersion !== '1.0' || root.capability !== 'INVENTORY' || root.platform !== 'HYPERV' || root.transport !== 'LOCAL_CIM_V2' || root.mutationAttempted !== false) throw new Error('Hyper-V CIM output violated the signed contract')
  if (!UUID.test(context.collectionRunId) || Number.isNaN(Date.parse(context.collectedAt)) || !context.connectorVersion) throw new Error('Hyper-V CIM context is invalid')
  if (!root.host || typeof root.host !== 'object' || Array.isArray(root.host)) throw new Error('Hyper-V CIM host is missing')
  const host = root.host as Record<string, unknown>; const hostUid = normalizeUuid(host.UUID, 'host.UUID')
  const records: HypervCimAsset[] = [{ kind: 'HOST', sourceUid: hostUid, name: string(host.Name, 'host.Name', 253), attributes: scalars(host, new Set(['UUID', 'Name'])), relationships: {} }]
  const seen = new Set([`HOST:${hostUid}`])
  const systems = rows(root.computerSystems ?? [], 'computerSystems')
  const vmUids = new Set(systems.map((system) => String(system.Name ?? '').toLowerCase()).filter((uid) => UUID.test(uid)))
  const processors = keyedSettings(root.processors, 'processors', vmUids); const memory = keyedSettings(root.memory, 'memory', vmUids)
  for (const system of systems) {
    const rawId = String(system.Name ?? '')
    if (!UUID.test(rawId)) continue // the local hosting-computer object is not a VM
    const sourceUid = normalizeUuid(rawId, 'computerSystems.Name'); const key = `VIRTUAL_MACHINE:${sourceUid}`
    if (seen.has(key)) throw new Error(`Hyper-V CIM contains duplicate immutable identity ${key}`); seen.add(key)
    const processor = processors.get(sourceUid); const memorySetting = memory.get(sourceUid)
    if (!processor || !memorySetting) throw new Error(`Hyper-V CIM VM ${sourceUid} lacks processor or memory allocation settings`)
    const vCpuCount = Number(processor.VirtualQuantity)
    if (!Number.isSafeInteger(vCpuCount) || vCpuCount <= 0) throw new Error(`Hyper-V CIM VM ${sourceUid} has invalid processor allocation`)
    records.push({ kind: 'VIRTUAL_MACHINE', sourceUid, name: string(system.ElementName, 'computerSystems.ElementName', 253), attributes: { ...scalars(system, new Set(['Name', 'ElementName'])), vCpuCount, memoryBytes: memoryBytes(memorySetting) }, relationships: { host: hostUid } })
  }
  for (const setting of rows(root.settings ?? [], 'settings')) {
    const rawVmUid = String(setting.VirtualSystemIdentifier ?? '').trim()
    if (!rawVmUid) continue // Hyper-V returns platform/version definition rows alongside realized VM settings.
    const vmUid = normalizeUuid(rawVmUid, 'settings.VirtualSystemIdentifier')
    const sourceIdentifier = string(setting.InstanceID, 'settings.InstanceID', 1024)
    const sourceUid = createHash('sha256').update(`hyperv-setting|${hostUid}|${sourceIdentifier}`).digest('hex')
    const kind: HypervCimAssetKind = Number(setting.SettingType) === 5 ? 'CHECKPOINT' : 'VM_CONFIGURATION'
    const key = `${kind}:${sourceUid}`; if (seen.has(key)) throw new Error(`Hyper-V CIM contains duplicate immutable identity ${key}`); seen.add(key)
    records.push({ kind, sourceUid, name: string(setting.ElementName, 'settings.ElementName', 253), attributes: { ...scalars(setting, new Set(['ElementName', 'VirtualSystemIdentifier'])), rawSourceId: sourceIdentifier }, relationships: { virtualMachine: vmUid, host: hostUid } })
  }
  const unavailable = root.unavailableFamilies
  if (!Array.isArray(unavailable) || requiredUnavailable.some((item) => !unavailable.includes(item))) throw new Error('Hyper-V CIM reduced-coverage declaration is incomplete')
  if (root.clusterAvailable === true) {
    if (!root.cluster || typeof root.cluster !== 'object' || Array.isArray(root.cluster)) throw new Error('Hyper-V failover cluster is missing')
    const cluster = root.cluster as Record<string, unknown>; const clusterUid = normalizeUuid(cluster.Id ?? cluster.ID, 'cluster.Id')
    const clusterNodes = rows(root.clusterNodes ?? [], 'clusterNodes')
    records.push({ kind: 'FAILOVER_CLUSTER', sourceUid: clusterUid, name: string(cluster.Name, 'cluster.Name', 253), attributes: { ...scalars(cluster, new Set(['Id', 'ID', 'Name'])), nodeNames: JSON.stringify(clusterNodes.map((node) => string(node.Name, 'clusterNodes.Name', 253)).sort()) }, relationships: { localHost: hostUid } })
  }
  const capabilities: Record<string, 'READY' | 'UNAVAILABLE'> = {}
  for (const item of ['HOST', 'VIRTUAL_MACHINE', 'VM_CONFIGURATION', 'CHECKPOINT', 'FAILOVER_CLUSTER']) capabilities[item] = item === 'FAILOVER_CLUSTER' && root.clusterAvailable !== true ? 'UNAVAILABLE' : 'READY'
  for (const item of requiredUnavailable) capabilities[item] = 'UNAVAILABLE'
  return { records, errors: [], page: { receivedCount: records.length, complete: true }, reducedCoverage: true, capabilities, provenance: { connectorId: 'cloudverse.hyperv.cim-v2', connectorVersion: context.connectorVersion, collectionRunId: context.collectionRunId, collectedAt: new Date(context.collectedAt).toISOString(), transport: 'LOCAL_CIM_V2' } }
}

export class HypervCimInventoryAdapter {
  constructor(private readonly runner: ConstrainedPowerShellRunner) {}
  async collect(context: ScvmmDiscoveryContext) { return normalizeHypervCimInventory(await this.runner.runLocalHypervCimInventory(), context) }
}
