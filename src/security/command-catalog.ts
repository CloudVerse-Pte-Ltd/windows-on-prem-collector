import { isIP } from 'node:net'

export type OperationId = 'scvmm.discovery.v1' | 'scvmm.inventory.v1' | 'hyperv.cim.inventory.v1' | 'hyperv.performance.v1'

export interface ScvmmDiscoveryParameters {
  server: string
  port?: number
}

export const COMMAND_CATALOG = Object.freeze({
  'scvmm.discovery.v1': Object.freeze({
    script: 'Discover-Scvmm.ps1',
    allowedCommands: Object.freeze([
      'ConvertTo-Json', 'Get-SCVMMServer', 'Get-SCUserRole', 'Get-SCVMHost', 'Import-Module', 'Select-Object', 'Set-StrictMode',
    ]),
    parameters: Object.freeze(['server', 'port']),
  }),
  'scvmm.inventory.v1': Object.freeze({
    script: 'Collect-ScvmmInventory.ps1',
    allowedCommands: Object.freeze([
      'ConvertTo-Json', 'Get-SCLogicalNetwork', 'Get-SCStorageArray', 'Get-SCStoragePool', 'Get-SCVirtualMachine',
      'Get-SCVMCheckpoint', 'Get-SCVMHost', 'Get-SCVMHostCluster', 'Get-SCVMHostGroup', 'Get-SCVMNetwork',
      'Get-SCVMTemplate', 'Get-SCVMMServer', 'Import-Module', 'Select-Object', 'Set-StrictMode',
    ]),
    parameters: Object.freeze(['server', 'port']),
  }),
  'hyperv.cim.inventory.v1': Object.freeze({
    script: 'Collect-HypervCimInventory.ps1',
    allowedCommands: Object.freeze(['ConvertTo-Json', 'Get-CimInstance', 'Set-StrictMode']),
    parameters: Object.freeze([]),
  }),
  'hyperv.performance.v1': Object.freeze({
    script: 'Collect-HypervPerformance.ps1',
    allowedCommands: Object.freeze(['ConvertTo-Json', 'Get-Counter', 'Get-VM', 'Set-StrictMode']),
    parameters: Object.freeze([]),
  }),
}) satisfies Record<OperationId, { script: string; allowedCommands: readonly string[]; parameters: readonly string[] }>

export function validateScvmmDiscoveryParameters(value: unknown): ScvmmDiscoveryParameters {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('SCVMM discovery parameters must be an object')
  const record = value as Record<string, unknown>
  const unexpected = Object.keys(record).filter((key) => !COMMAND_CATALOG['scvmm.discovery.v1'].parameters.includes(key))
  if (unexpected.length) throw new Error(`Unknown SCVMM discovery parameter: ${unexpected.join(',')}`)
  const server = typeof record.server === 'string' ? record.server.trim() : ''
  const ipLiteral = server.startsWith('[') && server.endsWith(']') ? server.slice(1, -1) : server
  const validDnsName = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i.test(server) && !/^[0-9.]+$/.test(server)
  if (!server || server.length > 253 || (!validDnsName && isIP(ipLiteral) === 0)) {
    throw new Error('SCVMM server must be a bounded DNS name or IP literal')
  }
  const port = record.port === undefined ? 8100 : record.port
  if (!Number.isSafeInteger(port) || Number(port) < 1 || Number(port) > 65535) throw new Error('SCVMM port must be an integer from 1 to 65535')
  return { server, port: Number(port) }
}
