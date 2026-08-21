export interface SignedScriptRecord {
  sha256: string
  signerThumbprints: string[]
}

export interface CollectorReleaseManifest {
  schemaVersion: 1
  catalogVersion: string
  scripts: Record<string, SignedScriptRecord>
}

export function parseReleaseManifest(value: unknown): CollectorReleaseManifest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Release manifest must be an object')
  const manifest = value as Partial<CollectorReleaseManifest>
  if (manifest.schemaVersion !== 1 || typeof manifest.catalogVersion !== 'string' || !manifest.catalogVersion || !manifest.scripts || typeof manifest.scripts !== 'object') throw new Error('Unsupported release manifest')
  for (const [name, record] of Object.entries(manifest.scripts)) {
    if (!/^[A-Za-z0-9.-]+\.ps1$/.test(name) || !record || !/^[0-9a-f]{64}$/i.test(record.sha256) || !Array.isArray(record.signerThumbprints) || !record.signerThumbprints.length || record.signerThumbprints.some((item) => !/^[0-9a-f]{40,64}$/i.test(item))) throw new Error(`Invalid signed script manifest entry: ${name}`)
  }
  return manifest as CollectorReleaseManifest
}
