import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { mkdir, open, readFile, readdir, rename, stat, unlink } from 'node:fs/promises'
import { isIP } from 'node:net'
import { join } from 'node:path'
import { Agent, Pool, ProxyAgent, fetch as undiciFetch, type Dispatcher } from 'undici'
import { redactWindowsCollectorError } from '../security/redaction.js'

interface Item { queueId: string; bundleId: string; schemaVersion: string; createdAt: string; attempts: number; nextAttemptAt: string; payload: Buffer; lastError?: string }
type Resolver = (hostname: string) => Promise<string[]>
type Sender = typeof undiciFetch
export interface WindowsProxyConfig { endpoint: string; allowedHosts: string[]; privateAddressAllowedHosts?: string[]; authorization: string }
const privateAddress = (address: string): boolean => {
  const value = address.toLowerCase()
  if (value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || /^fe[89ab]/.test(value) || value.startsWith('ff') || value.startsWith('2001:db8:')) return true
  if (value.startsWith('::ffff:')) return privateAddress(value.slice(7))
  const parts = value.split('.').map(Number)
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return false
  return parts.some((part) => part < 0 || part > 255) || parts[0] === 0 || parts[0] === 10 || parts[0] === 127 ||
    (parts[0] === 100 && parts[1]! >= 64 && parts[1]! <= 127) || (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) || (parts[0] === 192 && [0, 2, 168].includes(parts[1]!)) ||
    (parts[0] === 198 && [18, 19, 51].includes(parts[1]!)) || (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) || parts[0]! >= 224
}
const defaultResolver: Resolver = async (hostname) => (await lookup(hostname, { all: true })).map((row) => row.address)
const lookupPinned = (addresses: string[]) => (_hostname: string, options: any, callback: (...args: any[]) => void) => { const rows = addresses.map((address) => ({ address, family: isIP(address) })); options?.all ? callback(null, rows) : callback(null, rows[0]!.address, rows[0]!.family) }

export class EncryptedWindowsSpool {
  private tail: Promise<void> = Promise.resolve()
  constructor(private readonly config: { directory: string; key: Buffer; maxBytes: number; maxItems: number; acceptedSchemaVersions: string[] }) { if (config.key.length !== 32) throw new Error('Spool key must be 32 bytes'); if (!Number.isSafeInteger(config.maxBytes) || config.maxBytes <= 0 || !Number.isSafeInteger(config.maxItems) || config.maxItems <= 0) throw new Error('Positive spool bounds are required') }
  async initialize() { await mkdir(this.config.directory, { recursive: true }) }
  async enqueue(bundleId: string, schemaVersion: string, payload: Buffer) { return this.exclusive(async () => { await this.initialize(); const usage = await this.usage(); if (usage.items >= this.config.maxItems) throw new Error('COLLECTOR_SPOOL_BACKPRESSURE'); const now = new Date(); const item: Item = { queueId: `${now.valueOf().toString().padStart(13, '0')}-${randomUUID()}`, bundleId, schemaVersion, createdAt: now.toISOString(), attempts: 0, nextAttemptAt: now.toISOString(), payload }; const bytes = this.encrypt(item); if (usage.bytes + bytes.length + ((usage.items + 1) * 4096) > this.config.maxBytes) throw new Error('COLLECTOR_SPOOL_BACKPRESSURE'); await this.write(item.queueId, bytes); return item.queueId }) }
  async list() { await this.initialize(); const names = (await readdir(this.config.directory)).filter((name) => name.endsWith('.bundle')).sort(); return Promise.all(names.map(async (name) => this.decrypt(await readFile(join(this.config.directory, name))))) }
  async usage() { await this.initialize(); const names = (await readdir(this.config.directory)).filter((name) => name.endsWith('.bundle')); let bytes = 0; for (const name of names) bytes += (await stat(join(this.config.directory, name))).size; return { items: names.length, bytes } }
  accepts(version: string) { return this.config.acceptedSchemaVersions.includes(version) }
  async remove(queueId: string) { if (!/^[0-9]{13}-[0-9a-f-]{36}$/.test(queueId)) throw new Error('Invalid queue ID'); await unlink(join(this.config.directory, `${queueId}.bundle`)) }
  async update(item: Item) { await this.exclusive(async () => { const bytes = this.encrypt(item); const usage = await this.usage(); const existing = await stat(join(this.config.directory, `${item.queueId}.bundle`)); if (usage.bytes - existing.size + bytes.length > this.config.maxBytes) throw new Error('COLLECTOR_SPOOL_BACKPRESSURE'); await this.write(item.queueId, bytes) }) }
  private encrypt(item: Item) { const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', this.config.key, iv); const encrypted = Buffer.concat([cipher.update(JSON.stringify({ ...item, payload: item.payload.toString('base64') })), cipher.final()]); return Buffer.from(JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), encrypted: encrypted.toString('base64') })) }
  private decrypt(bytes: Buffer): Item { const envelope = JSON.parse(bytes.toString()); if (envelope.v !== 1) throw new Error('Unsupported spool envelope'); const decipher = createDecipheriv('aes-256-gcm', this.config.key, Buffer.from(envelope.iv, 'base64')); decipher.setAuthTag(Buffer.from(envelope.tag, 'base64')); const value = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.encrypted, 'base64')), decipher.final()]).toString()); return { ...value, payload: Buffer.from(value.payload, 'base64') } }
  private async write(id: string, bytes: Buffer) { const target = join(this.config.directory, `${id}.bundle`); const temp = `${target}.${randomUUID()}.tmp`; const handle = await open(temp, 'wx', 0o600); try { await handle.writeFile(bytes); await handle.sync() } finally { await handle.close() }; await rename(temp, target) }
  private async exclusive<T>(fn: () => Promise<T>) { const previous = this.tail; let release!: () => void; this.tail = new Promise<void>((resolve) => { release = resolve }); await previous; try { return await fn() } finally { release() } }
}

export class WindowsSpoolUploader {
  private lastError: string | null = null; private lastSuccessAt: string | null = null
  constructor(private readonly spool: EncryptedWindowsSpool, private readonly config: { endpoint: string; allowedHosts: string[]; privateAddressAllowedHosts?: string[]; bearerToken: string; proxy?: WindowsProxyConfig }, private readonly resolver: Resolver = defaultResolver, private readonly sender: Sender = undiciFetch) {}
  async flushOnce(now = new Date()) {
    const items = await this.spool.list(); let sent = 0; let deferred = 0; let incompatible = 0
    let url: URL; let addresses: string[]
    try {
      url = new URL(this.config.endpoint)
      if (url.protocol !== 'https:' || url.username || url.password || !this.config.allowedHosts.map((x) => x.toLowerCase()).includes(url.hostname.toLowerCase())) throw new Error('Upload endpoint is not approved credential-free HTTPS')
      addresses = await this.resolver(url.hostname)
      if (!addresses.length || (addresses.some(privateAddress) && !(this.config.privateAddressAllowedHosts ?? []).map((x) => x.toLowerCase()).includes(url.hostname.toLowerCase()))) throw new Error('Upload endpoint resolved to a prohibited address')
    } catch (error) {
      const message = redactWindowsCollectorError(error)
      for (const item of items) { if (!this.spool.accepts(item.schemaVersion)) { incompatible++; continue }; if (new Date(item.nextAttemptAt) > now) { deferred++; continue }; await this.defer(item, now, message); deferred++ }
      this.lastError = message
      return { examined: items.length, sent, deferred, incompatible }
    }
    let agent: Dispatcher
    if (this.config.proxy) {
      let proxyUrl: URL; let proxyAddresses: string[]
      try {
        proxyUrl = new URL(this.config.proxy.endpoint)
        if (proxyUrl.protocol !== 'https:' || proxyUrl.username || proxyUrl.password || !this.config.proxy.allowedHosts.map((x) => x.toLowerCase()).includes(proxyUrl.hostname.toLowerCase())) throw new Error('Proxy endpoint is not approved credential-free HTTPS')
        if (!/^(Basic|Bearer) [A-Za-z0-9+/_=.~-]+$/.test(this.config.proxy.authorization)) throw new Error('Proxy authorization value is invalid')
        proxyAddresses = await this.resolver(proxyUrl.hostname)
        if (!proxyAddresses.length || (proxyAddresses.some(privateAddress) && !(this.config.proxy.privateAddressAllowedHosts ?? []).map((x) => x.toLowerCase()).includes(proxyUrl.hostname.toLowerCase()))) throw new Error('Proxy endpoint resolved to a prohibited address')
      } catch (error) {
        const message = redactWindowsCollectorError(error)
        for (const item of items) { if (!this.spool.accepts(item.schemaVersion)) { incompatible++; continue }; if (new Date(item.nextAttemptAt) > now) { deferred++; continue }; await this.defer(item, now, message); deferred++ }
        this.lastError = message
        return { examined: items.length, sent, deferred, incompatible }
      }
      agent = new ProxyAgent({ uri: proxyUrl.toString(), token: this.config.proxy.authorization, clientFactory: (origin, options) => new Pool(origin, { ...options, connect: { ...((options as any).connect ?? {}), lookup: lookupPinned(proxyAddresses) } }) })
    } else agent = new Agent({ connect: { lookup: lookupPinned(addresses) } })
    try { for (const item of items) { if (!this.spool.accepts(item.schemaVersion)) { incompatible++; continue }; if (new Date(item.nextAttemptAt) > now) { deferred++; continue }; try { const response = await this.sender(url, { method: 'POST', dispatcher: agent, headers: { 'content-type': 'application/json', authorization: `Bearer ${this.config.bearerToken}`, 'x-bundle-id': item.bundleId, 'x-bundle-schema-version': item.schemaVersion }, body: item.payload }); if (!response.ok) throw new Error(`Upload returned HTTP ${response.status}`); await this.spool.remove(item.queueId); sent++; this.lastError = null; this.lastSuccessAt = now.toISOString() } catch (error) { await this.defer(item, now, redactWindowsCollectorError(error)); deferred++; this.lastError = item.lastError ?? 'Collector upload failed' } } } finally { await agent.close() }
    return { examined: items.length, sent, deferred, incompatible }
  }
  async health() { const items = await this.spool.list(); return { healthy: this.lastError === null && items.every((item) => this.spool.accepts(item.schemaVersion)), queue: await this.spool.usage(), incompatible: items.filter((item) => !this.spool.accepts(item.schemaVersion)).length, lastError: this.lastError, lastSuccessAt: this.lastSuccessAt } }
  private async defer(item: Item, now: Date, message: string) { item.attempts++; item.lastError = message; item.nextAttemptAt = new Date(now.valueOf() + Math.min(3_600_000, 1000 * 2 ** Math.min(item.attempts, 12))).toISOString(); await this.spool.update(item) }
}
