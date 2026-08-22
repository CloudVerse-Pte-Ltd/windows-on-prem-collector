import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { loadWindowsCollectorConfig } from '../../src/runtime/collector-runtime.js'

const directories: string[] = []
async function load(overrides: Record<string, unknown> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'cv-windows-config-')); directories.push(directory)
  const path = join(directory, 'collector.config.json')
  await writeFile(path, JSON.stringify({
    stateDirectory: 'state', spoolDirectory: 'spool', scriptsDirectory: 'scripts', manifestPath: 'release-manifest.json',
    managementPlaneUid: 'hyperv:11111111-1111-4111-8111-111111111111', mode: 'LOCAL_HYPERV', scaleClass: 'S', intervalSeconds: 60, maxSpoolBytes: 1024, maxSpoolItems: 10,
    offlineExportDirectory: 'export', executionBoundary: { kind: 'JEA', endpointName: 'CloudVerseCollector' }, ...overrides,
  }))
  return loadWindowsCollectorConfig(path)
}
afterEach(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))))

describe('Windows collector execution-boundary configuration', () => {
  it('accepts explicit packaged JEA and WDAC/AppLocker boundaries', async () => {
    await expect(load()).resolves.toMatchObject({ executionBoundary: { kind: 'JEA', endpointName: 'CloudVerseCollector' } })
    await expect(load({ executionBoundary: { kind: 'WDAC_APPLOCKER' } })).resolves.toMatchObject({ executionBoundary: { kind: 'WDAC_APPLOCKER' } })
  })
  it('fails closed when the boundary is absent, unknown, or injection-shaped', async () => {
    await expect(load({ executionBoundary: undefined })).rejects.toThrow('explicit JEA or WDAC')
    await expect(load({ executionBoundary: { kind: 'UNCONSTRAINED' } })).rejects.toThrow('explicit JEA or WDAC')
    await expect(load({ executionBoundary: { kind: 'JEA', endpointName: 'CloudVerse;Get-Process' } })).rejects.toThrow('endpoint name is invalid')
  })
  it('binds collector mode to the correct immutable management-plane kind', async () => {
    await expect(load({ managementPlaneUid: 'scvmm:11111111-1111-4111-8111-111111111111' })).rejects.toThrow('Hyper-V host')
    await expect(load({ mode: 'SCVMM', managementPlaneUid: 'hyperv:11111111-1111-4111-8111-111111111111', scvmm: { server: 'vmm.example.com', port: 8100 } })).rejects.toThrow('SCVMM management-plane')
    await expect(load({ mode: 'SCVMM', managementPlaneUid: 'scvmm:11111111-1111-4111-8111-111111111111', scvmm: { server: 'vmm.example.com', port: 8100 } })).resolves.toMatchObject({ mode: 'SCVMM' })
  })
  it('rejects invalid spool bounds, missing paths, and empty upload allowlists', async () => {
    await expect(load({ maxSpoolBytes: 0 })).rejects.toThrow('Positive spool bounds')
    await expect(load({ scaleClass: undefined })).rejects.toThrow('scaleClass must be S, M, L or XL')
    await expect(load({ scaleClass: 'S', maxSpoolBytes: 10 * 1_073_741_824 + 1 })).rejects.toThrow('ratified S scale-class ceiling')
    await expect(load({ stateDirectory: '' })).rejects.toThrow('stateDirectory is required')
    await expect(load({ offlineExportDirectory: undefined, upload: { endpoint: 'https://cpd.example.test', allowedHosts: [] } })).rejects.toThrow('allowedHosts')
  })
  it('requires an explicit proxy allowlist and protected authorization-file reference', async () => {
    const upload = { endpoint: 'https://cpd.example.test', allowedHosts: ['cpd.example.test'] }
    await expect(load({ offlineExportDirectory: undefined, upload: { ...upload, proxy: { endpoint: 'https://proxy.example.test', allowedHosts: [], authorizationFile: 'proxy-auth' } } })).rejects.toThrow('Proxy allowedHosts')
    await expect(load({ offlineExportDirectory: undefined, upload: { ...upload, proxy: { endpoint: 'https://proxy.example.test', allowedHosts: ['proxy.example.test'], authorizationFile: '' } } })).rejects.toThrow('Proxy allowedHosts')
    await expect(load({ offlineExportDirectory: undefined, upload: { ...upload, proxy: { endpoint: 'https://proxy.example.test', allowedHosts: ['proxy.example.test'], authorizationFile: 'proxy-auth' } } })).resolves.toMatchObject({ upload: { proxy: { authorizationFile: 'proxy-auth' } } })
  })
})
