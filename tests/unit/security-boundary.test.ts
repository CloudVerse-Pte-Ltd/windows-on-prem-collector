import { createHash } from 'node:crypto'
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { COMMAND_CATALOG, ConstrainedPowerShellRunner, parseReleaseManifest, redactWindowsCollectorError, validateScvmmDiscoveryParameters } from '../../src/index.js'

const temporaryDirectories: string[] = []
const thumbprint = 'A'.repeat(40)

async function harness(options: { tamper?: boolean; signatureStatus?: string; signer?: string; jea?: boolean; inventoryPages?: unknown[] } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'cv-windows-collector-')); temporaryDirectories.push(directory)
  const script = Buffer.from('Get-SCVMMServer\n')
  const inventoryScript = Buffer.from('Get-SCVirtualMachine\n')
  const cimScript = Buffer.from('Get-CimInstance\n')
  const performanceScript = Buffer.from('Get-Counter\n')
  await writeFile(join(directory, 'Discover-Scvmm.ps1'), options.tamper ? Buffer.from('Set-SCVMMServer\n') : script)
  await writeFile(join(directory, 'Collect-ScvmmInventory.ps1'), inventoryScript)
  await writeFile(join(directory, 'Collect-HypervCimInventory.ps1'), cimScript)
  await writeFile(join(directory, 'Collect-HypervPerformance.ps1'), performanceScript)
  const manifestPath = join(directory, 'release-manifest.json')
  await writeFile(manifestPath, JSON.stringify({ schemaVersion: 1, catalogVersion: 'c25-v1', scripts: {
    'Discover-Scvmm.ps1': { sha256: createHash('sha256').update(script).digest('hex'), signerThumbprints: [thumbprint] },
    'Collect-ScvmmInventory.ps1': { sha256: createHash('sha256').update(inventoryScript).digest('hex'), signerThumbprints: [thumbprint] },
    'Collect-HypervCimInventory.ps1': { sha256: createHash('sha256').update(cimScript).digest('hex'), signerThumbprints: [thumbprint] },
    'Collect-HypervPerformance.ps1': { sha256: createHash('sha256').update(performanceScript).digest('hex'), signerThumbprints: [thumbprint] },
  } }))
  const executor = vi.fn(async (_file: string, args: readonly string[]) => args.includes('[string]$ExecutionContext.SessionState.LanguageMode') || args.includes('Get-CloudVerseExecutionBoundary')
    ? { stdout: options.jea ? 'NoLanguage\n' : 'ConstrainedLanguage\n', stderr: '' }
    : args.some((item) => item.includes('Get-AuthenticodeSignature')) ? { stdout: JSON.stringify({ Status: options.signatureStatus ?? 'Valid', Thumbprint: options.signer ?? thumbprint }), stderr: '' }
    : options.inventoryPages && args.includes('-PageNumber') ? { stdout: JSON.stringify(options.inventoryPages[Number(args[args.indexOf('-PageNumber') + 1])]), stderr: '' }
    : { stdout: JSON.stringify({ schemaVersion: '1.0', requestedRole: 'ReadOnlyAdmin' }), stderr: '' })
  return { runner: new ConstrainedPowerShellRunner({ scriptsDirectory: directory, manifestPath, executor, jeaEndpointName: options.jea ? 'CloudVerseCollector' : undefined, allowedScvmmEndpoints: [{ server: 'vmm01.example.com', port: 8100 }] }), executor, directory }
}

afterEach(async () => Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))))

describe('C24 Windows collector security boundary', () => {
  it('has a closed read-only command catalog with no mutation or generic execution cmdlets', () => {
    expect(Object.keys(COMMAND_CATALOG)).toEqual(['scvmm.discovery.v1', 'scvmm.inventory.v1', 'hyperv.cim.inventory.v1', 'hyperv.performance.v1'])
    const commands = Object.values(COMMAND_CATALOG).flatMap((operation) => [...operation.allowedCommands])
    expect(commands).toContain('Get-SCVMMServer')
    expect(commands.filter((command) => command !== 'Set-StrictMode').every((command) => !/^(Set|New|Remove|Start|Stop|Invoke)-/i.test(command))).toBe(true)
  })

  it('rejects unknown parameters and shell-shaped server values before execution', () => {
    expect(() => validateScvmmDiscoveryParameters({ server: 'vmm01.example.com', command: 'Get-Process' })).toThrow('Unknown')
    for (const server of ['vmm01;calc.exe', '$(Get-Process)', 'vmm01 example', '']) expect(() => validateScvmmDiscoveryParameters({ server })).toThrow('DNS name')
    expect(() => validateScvmmDiscoveryParameters({ server: '999.999.999.999' })).toThrow('DNS name')
    expect(validateScvmmDiscoveryParameters({ server: 'vmm01.example.com' })).toEqual({ server: 'vmm01.example.com', port: 8100 })
  })

  it('rejects executable substitution and non-allowlisted internal targets before process creation', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-windows-collector-')); temporaryDirectories.push(directory)
    expect(() => new ConstrainedPowerShellRunner({ scriptsDirectory: directory, manifestPath: join(directory, 'manifest.json'), powershellPath: 'C:\\Temp\\powershell.exe', allowedScvmmEndpoints: [{ server: 'vmm01.example.com', port: 8100 }] })).toThrow('canonical')
    const { runner, executor } = await harness(); await runner.initialize()
    await expect(runner.runScvmmDiscovery({ server: 'other-internal.example.com', port: 8100 })).rejects.toThrow('not allowlisted')
    expect(executor).toHaveBeenCalledTimes(5)
  })

  it('verifies digest and approved Authenticode signer before fixed argument-array execution', async () => {
    const { runner, executor, directory } = await harness(); await runner.initialize()
    await expect(runner.runScvmmDiscovery({ server: 'vmm01.example.com', port: 8100 })).resolves.toMatchObject({ requestedRole: 'ReadOnlyAdmin' })
    expect(executor).toHaveBeenCalledTimes(6)
    const [file, args] = executor.mock.calls[5]
    expect(file).toMatch(/powershell\.exe$/i)
    expect(args).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned', '-File', await realpath(resolve(directory, 'Discover-Scvmm.ps1')), '-Server', 'vmm01.example.com', '-Port', '8100'])
  })

  it('executes the CIM fallback locally with no caller-controlled arguments', async () => {
    const { runner, executor, directory } = await harness(); await runner.initialize()
    await runner.runLocalHypervCimInventory()
    const [file, args] = executor.mock.calls.at(-1)!
    expect(file).toMatch(/powershell\.exe$/i)
    expect(args).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned', '-File', await realpath(resolve(directory, 'Collect-HypervCimInventory.ps1'))])
  })

  it('executes Hyper-V performance collection locally with no caller-controlled arguments', async () => {
    const { runner, executor, directory } = await harness(); await runner.initialize()
    await runner.runLocalHypervPerformance()
    const [file, args] = executor.mock.calls.at(-1)!
    expect(file).toMatch(/powershell\.exe$/i)
    expect(args).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned', '-File', await realpath(resolve(directory, 'Collect-HypervPerformance.ps1'))])
  })

  it('executes only fixed catalog functions through an explicit NoLanguage JEA endpoint', async () => {
    const { runner, executor } = await harness({ jea: true }); await runner.initialize()
    await runner.runScvmmDiscovery({ server: 'vmm01.example.com', port: 8100 })
    const [, probe] = executor.mock.calls[0]
    expect(probe).toContain('CloudVerseCollector'); expect(probe).toContain('Get-CloudVerseExecutionBoundary')
    const [, operation] = executor.mock.calls.at(-1)!
    expect(operation).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned', '-ConfigurationName', 'CloudVerseCollector', '-Command', 'Invoke-CloudVerseScvmmDiscovery', '-Server', 'vmm01.example.com', '-Port', '8100'])
    expect(operation).not.toContain('-File')
  })

  it('collects SCVMM inventory in fixed source pages and validates completion metadata', async () => {
    const empty = { hostGroups: [], clusters: [], hosts: [], templates: [], checkpoints: [], storageArrays: [], storagePools: [], logicalNetworks: [], vmNetworks: [] }
    const contract = { schemaVersion: '1.0', capability: 'INVENTORY', platform: 'HYPERV', mutationAttempted: false }
    const { runner, executor } = await harness({ inventoryPages: [
      { ...contract, ...empty, virtualMachines: [{ ID: 'a' }], page: { number: 0, size: 2000, hasMore: true } },
      { ...contract, ...empty, virtualMachines: [{ ID: 'b' }], page: { number: 1, size: 2000, hasMore: false } },
    ] }); await runner.initialize()
    await expect(runner.runScvmmInventory({ server: 'vmm01.example.com', port: 8100 })).resolves.toMatchObject({ virtualMachines: [{ ID: 'a' }, { ID: 'b' }] })
    const operations = executor.mock.calls.filter(([, args]) => args.includes('-PageNumber'))
    expect(operations).toHaveLength(2); expect(operations[0]![1]).toContain('0'); expect(operations[1]![1]).toContain('1')
  })

  it('rejects unsafe JEA endpoint names before process creation', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-windows-jea-')); temporaryDirectories.push(directory)
    expect(() => new ConstrainedPowerShellRunner({ scriptsDirectory: directory, manifestPath: join(directory, 'manifest.json'), jeaEndpointName: 'endpoint;Get-Process' })).toThrow('JEA endpoint')
  })

  it('fails closed on changed bytes, invalid signature or unapproved signer', async () => {
    await expect((await harness({ tamper: true })).runner.initialize()).rejects.toThrow('digest mismatch')
    await expect((await harness({ signatureStatus: 'NotSigned' })).runner.initialize()).rejects.toThrow('Authenticode')
    await expect((await harness({ signer: 'B'.repeat(40) })).runner.initialize()).rejects.toThrow('Authenticode')
  })

  it('refuses startup when machine policy leaves PowerShell in FullLanguage mode', async () => {
    const { runner, executor } = await harness()
    executor.mockResolvedValueOnce({ stdout: 'FullLanguage\n', stderr: '' })
    await expect(runner.initialize()).rejects.toThrow('ConstrainedLanguage')
    expect(executor).toHaveBeenCalledTimes(1)
  })

  it('validates release manifest shape and redacts Windows credentials', () => {
    expect(() => parseReleaseManifest({ schemaVersion: 1, catalogVersion: 'v1', scripts: {} })).not.toThrow()
    expect(() => parseReleaseManifest({ schemaVersion: 2, catalogVersion: 'v2', scripts: {} })).toThrow('Unsupported')
    expect(redactWindowsCollectorError('credential=domain\\user:pass password=hunter2 token=abc')).not.toMatch(/hunter2|token=abc/)
  })

  it('the operational source contains only the reviewed command names', async () => {
    const source = await readFile(new URL('../../scripts/operations/Discover-Scvmm.ps1', import.meta.url), 'utf8')
    for (const command of ['Import-Module', 'Get-SCVMMServer', 'Get-SCUserRole', 'Get-SCVMHost', 'Select-Object', 'ConvertTo-Json']) expect(source).toContain(command)
    expect(source).not.toMatch(/\b(?:Set|New|Remove|Start|Stop|Invoke)-(?!StrictMode)\w+/)
    expect(source).toContain("requestedRole = 'ReadOnlyAdmin'")
    expect(source).toContain('mutationAttempted = $false')
  })

  it('the C25 inventory source is projection-only and covers every committed SCVMM family', async () => {
    const source = await readFile(new URL('../../scripts/operations/Collect-ScvmmInventory.ps1', import.meta.url), 'utf8')
    for (const command of ['Get-SCVMHostGroup', 'Get-SCVMHostCluster', 'Get-SCVMHost', 'Get-SCVirtualMachine', 'Get-SCVMTemplate', 'Get-SCVMCheckpoint', 'Get-SCStorageArray', 'Get-SCStoragePool', 'Get-SCLogicalNetwork', 'Get-SCVMNetwork']) expect(source).toContain(command)
    expect(source).not.toMatch(/\b(?:Set|New|Remove|Start|Stop|Invoke)-(?!StrictMode)\w+/)
    expect(source).toContain('mutationAttempted = $false')
  })

  it('the C26 fallback is fixed local CIM v2 collection with no remote target or mutation', async () => {
    const source = await readFile(new URL('../../scripts/operations/Collect-HypervCimInventory.ps1', import.meta.url), 'utf8')
    expect(source).toContain('root/virtualization/v2')
    expect(source).toContain('root/MSCluster')
    expect(source).not.toMatch(/-ComputerName|-CimSession|\b(?:Set|New|Remove|Start|Stop|Invoke)-(?!StrictMode)\w+/)
    expect(source).toContain('mutationAttempted = $false')
  })

  it('the C32 source uses only local read-only counters and emits explicit mapping gaps', async () => {
    const source = await readFile(new URL('../../scripts/operations/Collect-HypervPerformance.ps1', import.meta.url), 'utf8')
    for (const command of ['Get-VM', 'Get-Counter', 'ConvertTo-Json']) expect(source).toContain(command)
    expect(source).not.toContain('Select-Object')
    expect(source).not.toMatch(/-ComputerName|-CimSession|\b(?:Set|New|Remove|Start|Stop|Invoke)-(?!StrictMode)\w+/)
    expect(source).toContain('COUNTER_INSTANCE_VM_GUID_UNRESOLVED')
    expect(source).toContain("[regex]::Escape([string]$vm.Id)")
    expect(source).toContain("Scale = 1MB")
    expect(source).toContain("$sample.InstanceName -eq '_total'")
    expect(source).toContain('mutationAttempted = $false')
  })

})
