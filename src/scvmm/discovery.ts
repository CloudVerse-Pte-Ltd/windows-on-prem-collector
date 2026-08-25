import { ConstrainedPowerShellRunner } from '../security/powershell-runner.js'
import { ScvmmDiscoveryParameters, validateScvmmDiscoveryParameters } from '../security/command-catalog.js'

export interface ScvmmDiscoveryContext {
  collectionRunId: string
  collectedAt: string
  connectorVersion: string
}

export interface ScvmmManagementPlaneRecord {
  kind: 'SCVMM_MANAGEMENT_PLANE'
  sourceUid: string
  name: string
  productVersion: string
  port: number
  requestedRole: 'ReadOnlyAdmin'
  visibleRoles: Array<{ name: string; profile: string; description?: string }>
  hostReadProbe: Array<{ id: string; name: string; computerName: string; overallState: string }>
}

export interface ScvmmDiscoveryResult {
  records: ScvmmManagementPlaneRecord[]
  errors: []
  page: { receivedCount: 1; complete: true }
  health: { status: 'HEALTHY'; checkedAt: string; stale: false }
  provenance: {
    connectorId: 'cloudverse.hyperv.scvmm'
    connectorVersion: string
    collectedAt: string
    managementPlaneUid: string
    collectionRunId: string
    source: { endpoint: string; queryId: 'scvmm.discovery.v1'; metadata: { transport: 'SCVMM_POWERSHELL'; mutationAttempted: false } }
  }
  capabilities: Array<{ capability: 'AUTHENTICATE' | 'DESCRIBE_PLATFORM' | 'DISCOVER_PLANES' | 'DISCOVER_INVENTORY'; status: 'READY'; provenance: ScvmmDiscoveryResult['provenance'] }>
}

const SCVMM_CAPABILITIES: ReadonlyArray<ScvmmDiscoveryResult['capabilities'][number]['capability']> = [
  'AUTHENTICATE',
  'DESCRIBE_PLATFORM',
  'DISCOVER_PLANES',
  'DISCOVER_INVENTORY',
]

const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const ZERO_GUID = /^0{8}-0{4}-0{4}-0{4}-0{12}$/i

const boundedString = (value: unknown, field: string, maximum = 1024) => {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum) throw new Error(`SCVMM output ${field} is invalid`)
  return value.trim()
}
const boundedArray = (value: unknown, field: string, maximum: number) => {
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`SCVMM output ${field} is invalid`)
  return value
}

export function normalizeScvmmDiscoveryOutput(raw: unknown, parameters: ScvmmDiscoveryParameters, context: ScvmmDiscoveryContext): ScvmmDiscoveryResult {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('SCVMM discovery output must be an object')
  const value = raw as Record<string, unknown>
  if (value.schemaVersion !== '1.0' || value.capability !== 'INVENTORY' || value.platform !== 'HYPERV' || value.requestedRole !== 'ReadOnlyAdmin' || value.mutationAttempted !== false) throw new Error('SCVMM discovery output violated the signed discovery contract')
  if (!value.managementPlane || typeof value.managementPlane !== 'object' || Array.isArray(value.managementPlane)) throw new Error('SCVMM management plane is missing')
  const plane = value.managementPlane as Record<string, unknown>
  if (plane.port !== parameters.port) throw new Error('SCVMM output port does not match the approved endpoint')
  const name = boundedString(plane.name, 'managementPlane.name', 253)
  const version = boundedString(plane.version, 'managementPlane.version', 128)
  const managementPlaneId = boundedString(plane.id, 'managementPlane.id', 128).toLowerCase()
  if (!GUID_PATTERN.test(managementPlaneId) || ZERO_GUID.test(managementPlaneId)) throw new Error('SCVMM management plane lacks an immutable UUID')
  const visibleRoles = boundedArray(value.visibleRoles, 'visibleRoles', 100).map((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('SCVMM output visible role is invalid')
    const role = item as Record<string, unknown>
    return { name: boundedString(role.Name ?? role.name, 'role.name', 256), profile: boundedString(role.Profile ?? role.profile, 'role.profile', 128), ...((role.Description ?? role.description) ? { description: boundedString(role.Description ?? role.description, 'role.description', 1024) } : {}) }
  })
  const hostReadProbe = boundedArray(value.hostReadProbe, 'hostReadProbe', 1).map((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('SCVMM output host probe is invalid')
    const host = item as Record<string, unknown>
    return {
      id: (() => { const id = boundedString(host.ID ?? host.id, 'host.id', 128).toLowerCase(); if (!GUID_PATTERN.test(id) || ZERO_GUID.test(id)) throw new Error('SCVMM output host.id lacks an immutable GUID'); return id })(), name: boundedString(host.Name ?? host.name, 'host.name', 253),
      computerName: boundedString(host.ComputerName ?? host.computerName, 'host.computerName', 253), overallState: boundedString(host.OverallState ?? host.overallState, 'host.overallState', 128),
    }
  })
  if (!UUID_PATTERN.test(context.collectionRunId) || Number.isNaN(new Date(context.collectedAt).valueOf()) || !context.connectorVersion) throw new Error('SCVMM discovery context is invalid')
  const endpoint = `${parameters.server.toLowerCase()}:${parameters.port}`
  const managementPlaneUid = `scvmm:${managementPlaneId}`
  const provenance: ScvmmDiscoveryResult['provenance'] = {
    connectorId: 'cloudverse.hyperv.scvmm', connectorVersion: context.connectorVersion, collectedAt: new Date(context.collectedAt).toISOString(), managementPlaneUid,
    collectionRunId: context.collectionRunId, source: { endpoint: `scvmm://${endpoint}`, queryId: 'scvmm.discovery.v1', metadata: { transport: 'SCVMM_POWERSHELL', mutationAttempted: false } },
  }
  const record: ScvmmManagementPlaneRecord = { kind: 'SCVMM_MANAGEMENT_PLANE', sourceUid: managementPlaneUid, name, productVersion: version, port: parameters.port!, requestedRole: 'ReadOnlyAdmin', visibleRoles, hostReadProbe }
  return {
    records: [record], errors: [], page: { receivedCount: 1, complete: true }, health: { status: 'HEALTHY', checkedAt: provenance.collectedAt, stale: false }, provenance,
    capabilities: SCVMM_CAPABILITIES.map((capability) => ({ capability, status: 'READY', provenance })),
  }
}

export class ScvmmDiscoveryAdapter {
  constructor(private readonly runner: ConstrainedPowerShellRunner) {}
  async discover(parameters: unknown, context: ScvmmDiscoveryContext) {
    const approved = validateScvmmDiscoveryParameters(parameters)
    return normalizeScvmmDiscoveryOutput(await this.runner.runScvmmDiscovery(approved), approved, context)
  }
}
