import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { platform, tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { generateTransportCredential } from '../../src/security/transport-credential.js'

describe('collector transport credential', () => {
  it('writes the secret once and returns only its SHA-256 enrollment hash', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cv-collector-token-'))
    try {
      const tokenPath = join(directory, 'transport-token')
      const result = await generateTransportCredential(tokenPath)
      const token = (await readFile(tokenPath, 'utf8')).trim()

      expect(token.length).toBeGreaterThanOrEqual(32)
      expect(result).toEqual({
        tokenPath,
        transportTokenHash: createHash('sha256').update(token).digest('hex'),
      })
      expect(JSON.stringify(result)).not.toContain(token)
      if (platform() !== 'win32') {
        expect((await stat(tokenPath)).mode & 0o777).toBe(0o600)
      }
      await expect(generateTransportCredential(tokenPath)).rejects.toThrow()
    } finally {
      await rm(directory, { recursive: true })
    }
  })
})
