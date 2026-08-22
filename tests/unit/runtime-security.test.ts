import { generateKeyPairSync, verify } from 'node:crypto'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { EncryptedWindowsSpool } from '../../src/runtime/encrypted-spool.js'
import { enrollWindowsCollector, statePaths } from '../../src/runtime/enrollment.js'
import { canonicalBundleJson, WindowsBundleSigner } from '../../src/runtime/signed-bundle.js'

describe('Windows collector runtime security', () => {
  it('enrolls with public material and never sends generated secrets', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cv-win-enroll-')); const requests: any[] = []
    const transport = vi.fn(async (url: any, init: any) => { requests.push({ url: String(url), body: JSON.parse(init.body) }); return new Response(null, { status: 201 }) }) as any
    const identity = await enrollWindowsCollector({ controlPlaneUrl: 'https://cpd.example.test/data-center-collector', orgId: 8, integrationId: 21, enrollmentToken: 'bootstrap-secret', stateDirectory: root }, transport)
    const paths = statePaths(root); const privateKey = await readFile(paths.privateKey, 'utf8'); const transportToken = await readFile(paths.transportToken, 'utf8')
    expect(identity.provider).toBe('HYPERV'); expect(requests[0].url).toBe('https://cpd.example.test/data-center-collector/enroll')
    expect(JSON.stringify(requests[0].body)).not.toContain(privateKey); expect(JSON.stringify(requests[0].body)).not.toContain(transportToken)
    expect(requests[0].body.transportTokenHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('encrypts spool contents and detects tampering', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-spool-')); const key = Buffer.alloc(32, 7)
    const spool = new EncryptedWindowsSpool({ directory, key, maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
    const queueId = await spool.enqueue('bundle-sensitive', '1.0', Buffer.from('customer-secret-payload'))
    const path = join(directory, `${queueId}.bundle`); const bytes = await readFile(path)
    expect(bytes.toString()).not.toContain('customer-secret-payload'); expect((await spool.list())[0]!.payload.toString()).toBe('customer-secret-payload')
    const envelope = JSON.parse(bytes.toString()); envelope.encrypted = Buffer.from('tampered').toString('base64')
    await import('node:fs/promises').then(({ writeFile }) => writeFile(path, JSON.stringify(envelope)))
    await expect(spool.list()).rejects.toThrow()
  })

  it('signs deterministic canonical bytes with Ed25519', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519'); const signer = new WindowsBundleSigner(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { orgId: 8, collectorId: 'dc-test', signatureKeyId: 'key-test' })
    const bundle = signer.create('018f6e32-4f14-7c1f-aab2-90a7ac957011', { z: 2, a: 1 }, new Date('2026-08-22T00:00:00Z'))
    const { signature, ...unsigned } = bundle
    expect(verify(null, Buffer.from(canonicalBundleJson(unsigned)), publicKey, Buffer.from(signature, 'base64'))).toBe(true)
    expect(canonicalBundleJson({ z: 2, a: 1 })).toBe('{"a":1,"z":2}')
  })

  it('fails closed on insecure enrollment transport', async () => {
    await expect(enrollWindowsCollector({ controlPlaneUrl: 'http://cpd.example.test', orgId: 1, integrationId: 1, enrollmentToken: 'x', stateDirectory: 'unused' })).rejects.toThrow('HTTPS')
  })
})
