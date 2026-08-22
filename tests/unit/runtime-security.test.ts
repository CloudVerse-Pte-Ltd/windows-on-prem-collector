import { generateKeyPairSync, verify } from 'node:crypto'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { EncryptedWindowsSpool, WindowsSpoolUploader } from '../../src/runtime/encrypted-spool.js'
import { enrollWindowsCollector, statePaths } from '../../src/runtime/enrollment.js'
import { canonicalBundleJson, WindowsBundleSigner } from '../../src/runtime/signed-bundle.js'
import { collectPerformanceForMode } from '../../src/runtime/collector-runtime.js'

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

  it('reuses one local identity after an ambiguous enrollment failure', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cv-win-enroll-retry-')); const bodies: any[] = []; let attempt = 0
    const transport = vi.fn(async (_url: any, init: any) => { bodies.push(JSON.parse(init.body)); attempt++; if (attempt === 1) throw new Error('connection closed after request'); return new Response(null, { status: 201 }) }) as any
    const config = { controlPlaneUrl: 'https://cpd.example.test/data-center-collector', orgId: 8, integrationId: 22, enrollmentToken: 'bootstrap-secret', stateDirectory: root }
    await expect(enrollWindowsCollector(config, transport)).rejects.toThrow('connection closed')
    const paths = statePaths(root); const firstPrivateKey = await readFile(paths.privateKey, 'utf8'); const pending = JSON.parse(await readFile(paths.pending, 'utf8'))
    const identity = await enrollWindowsCollector(config, transport)
    expect(identity.collectorId).toBe(pending.identity.collectorId); expect(await readFile(paths.privateKey, 'utf8')).toBe(firstPrivateKey)
    expect(bodies[1]).toMatchObject({ collectorId: bodies[0].collectorId, keyId: bodies[0].keyId, publicKeyPem: bodies[0].publicKeyPem, transportTokenHash: bodies[0].transportTokenHash })
    await expect(readFile(paths.pending, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
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

  it('does not misattribute local Hyper-V counters when SCVMM lacks endpoint context', async () => {
    const runner = { runLocalHypervPerformance: vi.fn() } as any
    await expect(collectPerformanceForMode('SCVMM', runner)).rejects.toThrow('configured endpoint')
    expect(runner.runLocalHypervPerformance).not.toHaveBeenCalled()
  })

  it('retains encrypted bundles across DNS failure and recovers without restart', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-win-outage-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 9), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
    await spool.enqueue('bundle-outage', '1.0', Buffer.from('signed-envelope'))
    let available = false
    const resolver = vi.fn(async () => { if (!available) throw new Error('lookup token=secret failed'); return ['8.8.8.8'] })
    const sender = vi.fn(async () => new Response(null, { status: 202 })) as any
    const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test/bundles', allowedHosts: ['ingest.example.test'], bearerToken: 'transport-secret' }, resolver, sender)
    const started = new Date(Date.now() + 1_000)
    await expect(uploader.flushOnce(started)).resolves.toMatchObject({ sent: 0, deferred: 1 })
    expect(await spool.usage()).toMatchObject({ items: 1 }); expect((await uploader.health()).lastError).not.toContain('secret')
    available = true
    await expect(uploader.flushOnce(new Date(started.valueOf() + 2_000))).resolves.toMatchObject({ sent: 1 })
    expect(await spool.usage()).toMatchObject({ items: 0 }); expect(await uploader.health()).toMatchObject({ healthy: true, lastError: null })
  })

  it.each(['10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.1.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '2001:db8::1', '::ffff:127.0.0.1'])(
    'rejects prohibited upload address %s without losing the bundle', async (address) => {
      const directory = await mkdtemp(join(tmpdir(), 'cv-win-ssrf-')); const spool = new EncryptedWindowsSpool({ directory, key: Buffer.alloc(32, 5), maxBytes: 1_000_000, maxItems: 10, acceptedSchemaVersions: ['1.0'] })
      await spool.enqueue(`bundle-${address}`, '1.0', Buffer.from('payload'))
      const sender = vi.fn() as any; const uploader = new WindowsSpoolUploader(spool, { endpoint: 'https://ingest.example.test', allowedHosts: ['ingest.example.test'], bearerToken: 'token' }, async () => [address], sender)
      await expect(uploader.flushOnce(new Date('2026-08-22T00:00:00Z'))).resolves.toMatchObject({ sent: 0, deferred: 1 })
      expect(sender).not.toHaveBeenCalled(); expect(await spool.usage()).toMatchObject({ items: 1 })
    },
  )
})
