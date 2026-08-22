import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises'
import { dirname, join } from 'node:path'

export interface WindowsCollectorIdentity { collectorId: string; keyId: string; orgId: number; integrationId: number; provider: 'HYPERV'; enrolledAt: string }
export const statePaths = (root: string) => ({ identity: join(root, 'identity.json'), privateKey: join(root, 'signing-private.pem'), publicKey: join(root, 'signing-public.pem'), transportToken: join(root, 'transport-token'), spoolKey: join(root, 'spool-key') })
async function atomic(path: string, value: string) { await mkdir(dirname(path), { recursive: true }); const temporary = `${path}.${randomUUID()}.tmp`; const handle = await open(temporary, 'wx', 0o600); try { await handle.writeFile(value); await handle.sync() } finally { await handle.close() }; await rename(temporary, path) }

export async function enrollWindowsCollector(config: { controlPlaneUrl: string; orgId: number; integrationId: number; enrollmentToken: string; stateDirectory: string }, transport: typeof fetch = fetch) {
  if (!Number.isSafeInteger(config.orgId) || config.orgId <= 0 || !Number.isSafeInteger(config.integrationId) || config.integrationId <= 0) throw new Error('Positive orgId and integrationId are required')
  const endpoint = new URL(config.controlPlaneUrl); if (endpoint.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(endpoint.hostname)) throw new Error('Collector enrollment requires HTTPS')
  endpoint.pathname = `${endpoint.pathname.replace(/\/$/, '')}/enroll`
  const paths = statePaths(config.stateDirectory)
  try { return JSON.parse(await readFile(paths.identity, 'utf8')) as WindowsCollectorIdentity } catch (error: any) { if (error?.code !== 'ENOENT') throw error }
  const collectorId = `dc-${randomUUID()}`; const keyId = `key-${randomUUID()}`; const transportToken = randomBytes(32).toString('base64url')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519'); const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(); const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  await atomic(paths.privateKey, privateKeyPem); await atomic(paths.publicKey, publicKeyPem); await atomic(paths.transportToken, transportToken); await atomic(paths.spoolKey, randomBytes(32).toString('base64'))
  const response = await transport(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ orgId: config.orgId, integrationId: config.integrationId, enrollmentToken: config.enrollmentToken, collectorId, keyId, publicKeyPem, transportTokenHash: createHash('sha256').update(transportToken).digest('hex') }) })
  if (!response.ok) throw new Error(`Collector enrollment failed with HTTP ${response.status}`)
  const identity: WindowsCollectorIdentity = { collectorId, keyId, orgId: config.orgId, integrationId: config.integrationId, provider: 'HYPERV', enrolledAt: new Date().toISOString() }
  await atomic(paths.identity, JSON.stringify(identity)); return identity
}
export async function consumeEnrollmentTokenFile(path?: string) { if (path) await unlink(path).catch((error: any) => { if (error?.code !== 'ENOENT') throw error }) }
