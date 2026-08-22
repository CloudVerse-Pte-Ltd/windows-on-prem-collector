import { describe, expect, it } from 'vitest'
import { normalizeScvmmInventoryOutput } from '../../src/scvmm/inventory.js'
import { toHypervCollectionPayload, toHypervInventoryEnvelope, toHypervTelemetryEnvelope } from '../../src/hyperv/canonical-envelope.js'
import { generateKeyPairSync } from 'node:crypto'
import { WindowsBundleSigner } from '../../src/runtime/signed-bundle.js'

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
const context = { collectionRunId: id(999), collectedAt: '2026-08-21T00:00:00Z', connectorVersion: '0.1.0' }
const base = { schemaVersion: '1.0', capability: 'INVENTORY', platform: 'HYPERV', mutationAttempted: false }

describe('C25 SCVMM inventory normalization', () => {
  it('normalizes every committed family with immutable IDs and explicit relationships', () => {
    const row = (n: number, extra = {}) => ({ ID: id(n), Name: `asset-${n}`, ...extra })
    const raw = { ...base,
      hostGroups: [row(1)], clusters: [row(2, { VMHostGroup: { ID: id(1) } })], hosts: [row(3, { HostCluster: { ID: id(2) }, LogicalProcessorCount: 32 })],
      virtualMachines: [row(4, { VMHost: { ID: id(3) }, CPUCount: 4 })], templates: [row(5)], checkpoints: [row(6, { VM: { ID: id(4) } })],
      storageArrays: [row(7)], storagePools: [row(8, { StorageArray: { ID: id(7) } })], logicalNetworks: [row(9)], vmNetworks: [row(10, { LogicalNetwork: { ID: id(9) } })],
    }
    const result = normalizeScvmmInventoryOutput(raw, { server: 'VMM01.EXAMPLE.COM', port: 8100 }, context)
    expect(result.records).toHaveLength(10)
    expect(result.records[3]).toMatchObject({ kind: 'VIRTUAL_MACHINE', sourceUid: id(4), relationships: { VMHost: id(3) }, attributes: { CPUCount: 4 } })
    expect(result.page).toEqual({ receivedCount: 10, complete: true })
    expect(result.provenance.source.endpoint).toBe('scvmm://vmm01.example.com:8100')
  })

  it('rejects names as identity, duplicate GUIDs, mutation claims and over-bound families', () => {
    expect(() => normalizeScvmmInventoryOutput({ ...base, hosts: [{ Name: 'host-only' }] }, { server: 'vmm01', port: 8100 }, context)).toThrow('immutable GUID')
    expect(() => normalizeScvmmInventoryOutput({ ...base, hosts: [{ ID: id(1), Name: 'a' }, { ID: id(1), Name: 'renamed' }] }, { server: 'vmm01', port: 8100 }, context)).toThrow('duplicate')
    expect(() => normalizeScvmmInventoryOutput({ ...base, mutationAttempted: true }, { server: 'vmm01', port: 8100 }, context)).toThrow('signed contract')
    expect(() => normalizeScvmmInventoryOutput({ ...base, hosts: Array.from({ length: 100_001 }, (_, n) => ({ ID: id(n), Name: 'x' })) }, { server: 'vmm01', port: 8100 }, context)).toThrow('scale bound')
  })

  it('normalizes and signs the complete 15,000-VM reference estate within bounded transport size', () => {
    const virtualMachines = Array.from({ length: 15_000 }, (_, n) => ({ ID: id(n + 1), Name: `vm-${n + 1}`, Status: 'Running', CPUCount: 4, Memory: 8192, TotalSize: 137438953472 }))
    const raw = { ...base, hostGroups: [], clusters: [], hosts: [], virtualMachines, templates: [], checkpoints: [], storageArrays: [], storagePools: [], logicalNetworks: [], vmNetworks: [] }
    expect(Buffer.byteLength(JSON.stringify(raw))).toBeLessThanOrEqual(10 * 1024 * 1024)
    const started = performance.now(); const inventory = normalizeScvmmInventoryOutput(raw, { server: 'vmm01', port: 8100 }, context)
    expect(inventory.records).toHaveLength(15_000); expect(inventory.page).toEqual({ receivedCount: 15_000, complete: true })
    const inventoryEnvelope = toHypervInventoryEnvelope(1, `scvmm:${id(9999)}`, inventory)
    const telemetryEnvelope = toHypervTelemetryEnvelope(1, `scvmm:${id(9999)}`, context.collectedAt, [], [{ code: 'HOST_LEVEL_PERFORMANCE_COLLECTOR_REQUIRED' }])
    const { privateKey } = generateKeyPairSync('ed25519'); const signer = new WindowsBundleSigner(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { orgId: 1, collectorId: 'scale-fixture', signatureKeyId: 'scale-key' })
    const bundle = signer.create(context.collectionRunId, toHypervCollectionPayload(inventoryEnvelope, telemetryEnvelope, 'M'), new Date(context.collectedAt))
    expect(bundle.signature).toMatch(/^[A-Za-z0-9+/]+=*$/); expect(performance.now() - started).toBeLessThan(30_000)
  })
})
