import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, readFile, realpath } from 'node:fs/promises'
import { basename, dirname, join, resolve, win32 } from 'node:path'
import { promisify } from 'node:util'
import { COMMAND_CATALOG, OperationId, validateScvmmDiscoveryParameters } from './command-catalog.js'
import { CollectorReleaseManifest, parseReleaseManifest } from './release-manifest.js'
import { redactWindowsCollectorError } from './redaction.js'

const execFileAsync = promisify(execFile)
const FIXED_POWERSHELL_ARGUMENTS = Object.freeze(['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned'])
const WINDOWS_POWERSHELL_PATH = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
const AUTHENTICODE_PROBE = "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; [pscustomobject]@{Status=[string]$s.Status;Thumbprint=[string]$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress"
const LANGUAGE_MODE_PROBE = '[string]$ExecutionContext.SessionState.LanguageMode'
const JEA_LANGUAGE_MODE_PROBE = 'Get-CloudVerseExecutionBoundary'

export interface ProcessResult { stdout: string; stderr: string }
export type ProcessExecutor = (file: string, args: readonly string[], options: { timeout: number; maxBuffer: number; windowsHide: boolean }) => Promise<ProcessResult>
export interface PowerShellRunnerOptions {
  scriptsDirectory: string
  manifestPath: string
  powershellPath?: string
  jeaEndpointName?: string
  allowedScvmmEndpoints?: Array<{ server: string; port: number }>
  timeoutMs?: number
  executor?: ProcessExecutor
}

const defaultExecutor: ProcessExecutor = async (file, args, options) => execFileAsync(file, [...args], { ...options, encoding: 'utf8' })

export class ConstrainedPowerShellRunner {
  private readonly powershellPath: string
  private readonly executor: ProcessExecutor
  private manifest?: CollectorReleaseManifest

  constructor(private readonly options: PowerShellRunnerOptions) {
    this.powershellPath = options.powershellPath ?? WINDOWS_POWERSHELL_PATH
    if (win32.normalize(this.powershellPath).toLowerCase() !== win32.normalize(WINDOWS_POWERSHELL_PATH).toLowerCase()) throw new Error('Only the canonical Windows PowerShell executable is permitted')
    if (options.jeaEndpointName && !/^[A-Za-z][A-Za-z0-9.-]{0,63}$/.test(options.jeaEndpointName)) throw new Error('JEA endpoint name is invalid')
    this.executor = options.executor ?? defaultExecutor
  }

  async initialize() {
    this.manifest = parseReleaseManifest(JSON.parse(await readFile(this.options.manifestPath, 'utf8')))
    const languageMode = await this.executor(this.powershellPath, [...FIXED_POWERSHELL_ARGUMENTS, ...(this.options.jeaEndpointName ? ['-ConfigurationName', this.options.jeaEndpointName] : []), '-Command', this.options.jeaEndpointName ? JEA_LANGUAGE_MODE_PROBE : LANGUAGE_MODE_PROBE], { timeout: 30_000, maxBuffer: 64 * 1024, windowsHide: true })
    const expectedLanguageMode = this.options.jeaEndpointName ? 'NoLanguage' : 'ConstrainedLanguage'
    if (languageMode.stdout.trim() !== expectedLanguageMode) throw new Error(`Windows PowerShell must run in ${expectedLanguageMode} mode under the configured ${this.options.jeaEndpointName ? 'JEA' : 'WDAC/AppLocker'} boundary`)
    for (const [operationId, operation] of Object.entries(COMMAND_CATALOG)) await this.verifyScript(operationId as OperationId, operation.script)
  }

  async runScvmmDiscovery(parameters: unknown) {
    return this.runScvmmOperation('scvmm.discovery.v1', parameters)
  }

  async runScvmmInventory(parameters: unknown) {
    const families = ['hostGroups', 'clusters', 'hosts', 'virtualMachines', 'templates', 'checkpoints', 'storageArrays', 'storagePools', 'logicalNetworks', 'vmNetworks'] as const
    const combined: Record<string, unknown> = {}; for (const family of families) combined[family] = []
    for (let pageNumber = 0; pageNumber <= 50; pageNumber++) {
      const page = await this.runScvmmOperation('scvmm.inventory.v1', parameters, ['-PageNumber', String(pageNumber), '-PageSize', '2000']) as Record<string, unknown>
      const metadata = page.page as Record<string, unknown> | undefined
      if (!metadata || metadata.number !== pageNumber || metadata.size !== 2000 || typeof metadata.hasMore !== 'boolean') throw new Error('SCVMM inventory page metadata is invalid')
      for (const family of families) {
        if (!Array.isArray(page[family])) throw new Error(`SCVMM inventory page ${family} is invalid`)
        ;(combined[family] as unknown[]).push(...page[family] as unknown[])
      }
      for (const field of ['schemaVersion', 'capability', 'platform', 'mutationAttempted']) if (pageNumber === 0) combined[field] = page[field]; else if (page[field] !== combined[field]) throw new Error('SCVMM inventory page contract changed during collection')
      if (!metadata.hasMore) return combined
    }
    throw new Error('SCVMM inventory exceeded the 100,000-VM page bound')
  }

  async runLocalHypervCimInventory() {
    if (!this.manifest) throw new Error('PowerShell runner is not initialized')
    const operation = COMMAND_CATALOG['hyperv.cim.inventory.v1']; const scriptPath = await this.scriptPath(operation.script)
    try {
      const result = await this.executor(this.powershellPath, this.operationArguments(operation.jeaFunction, scriptPath), {
        timeout: this.options.timeoutMs ?? 120_000, maxBuffer: 20 * 1024 * 1024, windowsHide: true,
      })
      if (result.stderr.trim()) throw new Error(result.stderr)
      return JSON.parse(result.stdout)
    } catch (error) { throw new Error(redactWindowsCollectorError(error)) }
  }

  async runLocalHypervPerformance() {
    return this.runFixedLocalOperation('hyperv.performance.v1', 20 * 1024 * 1024)
  }

  private async runFixedLocalOperation(operationId: 'hyperv.performance.v1', maxBuffer: number) {
    if (!this.manifest) throw new Error('PowerShell runner is not initialized')
    const operation = COMMAND_CATALOG[operationId]; const scriptPath = await this.scriptPath(operation.script)
    try {
      const result = await this.executor(this.powershellPath, this.operationArguments(operation.jeaFunction, scriptPath), { timeout: this.options.timeoutMs ?? 120_000, maxBuffer, windowsHide: true })
      if (result.stderr.trim()) throw new Error(result.stderr)
      return JSON.parse(result.stdout)
    } catch (error) { throw new Error(redactWindowsCollectorError(error)) }
  }

  private async runScvmmOperation(operationId: OperationId, parameters: unknown, fixedParameters: string[] = []) {
    if (!this.manifest) throw new Error('PowerShell runner is not initialized')
    const value = validateScvmmDiscoveryParameters(parameters)
    if (!(this.options.allowedScvmmEndpoints ?? []).some((endpoint) => endpoint.server.toLowerCase() === value.server.toLowerCase() && endpoint.port === value.port)) throw new Error('SCVMM endpoint is not allowlisted')
    const operation = COMMAND_CATALOG[operationId]; const scriptPath = await this.scriptPath(operation.script)
    try {
      const result = await this.executor(this.powershellPath, this.operationArguments(operation.jeaFunction, scriptPath, ['-Server', value.server, '-Port', String(value.port), ...fixedParameters]), {
        timeout: this.options.timeoutMs ?? 120_000, maxBuffer: 10 * 1024 * 1024, windowsHide: true,
      })
      if (result.stderr.trim()) throw new Error(result.stderr)
      return JSON.parse(result.stdout)
    } catch (error) {
      throw new Error(redactWindowsCollectorError(error))
    }
  }

  private async verifyScript(operationId: OperationId, scriptName: string) {
    const scriptPath = await this.scriptPath(scriptName); const bytes = await readFile(scriptPath)
    const expected = this.manifest!.scripts[scriptName]
    if (!expected) throw new Error(`Release manifest omits ${operationId}`)
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (digest !== expected.sha256.toLowerCase()) throw new Error(`Script digest mismatch for ${operationId}`)
    const result = await this.executor(this.powershellPath, [...FIXED_POWERSHELL_ARGUMENTS, '-Command', AUTHENTICODE_PROBE, scriptPath], { timeout: 30_000, maxBuffer: 64 * 1024, windowsHide: true })
    const signature = JSON.parse(result.stdout) as { Status?: string; Thumbprint?: string }
    const thumbprint = String(signature.Thumbprint ?? '').replace(/\s/g, '').toUpperCase()
    if (signature.Status !== 'Valid' || !expected.signerThumbprints.map((item) => item.toUpperCase()).includes(thumbprint)) throw new Error(`Authenticode verification failed for ${operationId}`)
  }

  private operationArguments(jeaFunction: string, scriptPath: string, parameters: string[] = []) {
    return this.options.jeaEndpointName
      ? [...FIXED_POWERSHELL_ARGUMENTS, '-ConfigurationName', this.options.jeaEndpointName, '-Command', jeaFunction, ...parameters]
      : [...FIXED_POWERSHELL_ARGUMENTS, '-File', scriptPath, ...parameters]
  }

  private async scriptPath(scriptName: string) {
    if (basename(scriptName) !== scriptName) throw new Error('Catalog script path must be a file name')
    const root = await realpath(this.options.scriptsDirectory); const candidate = resolve(join(root, scriptName))
    if (dirname(candidate) !== root) throw new Error('Catalog script escaped the package directory')
    const details = await lstat(candidate)
    if (!details.isFile() || details.isSymbolicLink()) throw new Error('Catalog script must be a regular packaged file')
    return candidate
  }
}
