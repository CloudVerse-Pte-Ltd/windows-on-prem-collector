import { describe, expect, it, vi } from 'vitest'
import { normalizeScvmmDiscoveryOutput, ScvmmDiscoveryAdapter } from '../../src/index.js'

const parameters = { server: 'VMM01.example.com', port: 8100 }
const context = { collectionRunId: '11111111-1111-4111-8111-111111111111', collectedAt: '2026-08-21T00:00:00Z', connectorVersion: '0.1.0' }
const raw = {
  schemaVersion: '1.0', capability: 'INVENTORY', platform: 'HYPERV', requestedRole: 'ReadOnlyAdmin', mutationAttempted: false,
  managementPlane: { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'VMM01', version: '2025.1', port: 8100 },
  visibleRoles: [{ Name: 'CloudVerse Read Only', Profile: 'ReadOnlyAdmin' }],
  hostReadProbe: [{ ID: 'bbbbbbbb-bbbb-0bbb-0bbb-bbbbbbbbbbbb', Name: 'HV01', ComputerName: 'hv01.example.com', OverallState: 'OK' }],
}

describe('SCVMM discovery normalization', () => {
  it('emits the shared connector result shape with immutable SCVMM identity and provenance', () => {
    const result = normalizeScvmmDiscoveryOutput(raw, parameters, context)
    expect(result).toMatchObject({
      page: { receivedCount: 1, complete: true }, health: { status: 'HEALTHY', stale: false },
      records: [{ kind: 'SCVMM_MANAGEMENT_PLANE', requestedRole: 'ReadOnlyAdmin', port: 8100 }],
      provenance: { connectorId: 'cloudverse.hyperv.scvmm', collectionRunId: context.collectionRunId, source: { endpoint: 'scvmm://vmm01.example.com:8100', queryId: 'scvmm.discovery.v1' } },
    })
    expect(result.provenance.managementPlaneUid).toBe('scvmm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    expect(result.capabilities.map((item) => item.capability)).toEqual(['AUTHENTICATE', 'DESCRIBE_PLATFORM', 'DISCOVER_PLANES', 'DISCOVER_INVENTORY'])
  })

  it('keeps management-plane identity stable across display-name and version changes', () => {
    const first = normalizeScvmmDiscoveryOutput(raw, parameters, context)
    const changed = normalizeScvmmDiscoveryOutput({ ...raw, managementPlane: { ...raw.managementPlane, name: 'Renamed VMM', version: '2025.2' } }, parameters, context)
    expect(changed.provenance.managementPlaneUid).toBe(first.provenance.managementPlaneUid)
  })

  it('rejects contract drift, mutation claims, endpoint substitution and unbounded probes', () => {
    expect(() => normalizeScvmmDiscoveryOutput({ ...raw, platform: 'VSPHERE' }, parameters, context)).toThrow('contract')
    expect(() => normalizeScvmmDiscoveryOutput({ ...raw, mutationAttempted: true }, parameters, context)).toThrow('contract')
    expect(() => normalizeScvmmDiscoveryOutput({ ...raw, managementPlane: { ...raw.managementPlane, port: 9999 } }, parameters, context)).toThrow('approved endpoint')
    expect(() => normalizeScvmmDiscoveryOutput({ ...raw, managementPlane: { ...raw.managementPlane, id: '' } }, parameters, context)).toThrow('managementPlane.id')
    expect(() => normalizeScvmmDiscoveryOutput({ ...raw, hostReadProbe: [{ ...raw.hostReadProbe[0], ID: 'host-name' }] }, parameters, context)).toThrow('immutable GUID')
    expect(() => normalizeScvmmDiscoveryOutput(raw, parameters, { ...context, collectionRunId: '00000000-0000-0000-0000-000000000000' })).toThrow('context')
    expect(() => normalizeScvmmDiscoveryOutput({ ...raw, hostReadProbe: [raw.hostReadProbe[0], raw.hostReadProbe[0]] }, parameters, context)).toThrow('hostReadProbe')
  })

  it('routes only validated output through the constrained runner', async () => {
    const runner = { runScvmmDiscovery: vi.fn(async () => raw) }
    const adapter = new ScvmmDiscoveryAdapter(runner as any)
    await expect(adapter.discover(parameters, context)).resolves.toMatchObject({ records: [{ name: 'VMM01' }] })
    expect(runner.runScvmmDiscovery).toHaveBeenCalledWith({ server: 'VMM01.example.com', port: 8100 })
  })
})
