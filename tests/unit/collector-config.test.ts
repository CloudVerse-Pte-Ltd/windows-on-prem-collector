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
    managementPlaneUid: 'fixture', mode: 'LOCAL_HYPERV', intervalSeconds: 60, maxSpoolBytes: 1024, maxSpoolItems: 10,
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
})
