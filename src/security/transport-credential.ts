import { createHash, randomBytes } from 'node:crypto'
import { open } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export async function generateTransportCredential(tokenPath: string) {
  const resolvedPath = resolve(tokenPath)
  const token = randomBytes(32).toString('base64url')
  const handle = await open(resolvedPath, 'wx', 0o600)
  try {
    await handle.writeFile(`${token}\n`, { encoding: 'utf8' })
    await handle.sync()
  } finally {
    await handle.close()
  }
  return {
    tokenPath: resolvedPath,
    transportTokenHash: createHash('sha256').update(token).digest('hex'),
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const tokenPath = process.argv[2]
  if (!tokenPath) {
    process.stderr.write('Usage: node transport-credential.js <new-token-file>\n')
    process.exitCode = 2
  } else {
    generateTransportCredential(tokenPath)
      .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
      .catch((error) => {
        process.stderr.write(
          `Transport credential generation failed: ${
            error instanceof Error ? error.message : 'unknown error'
          }\n`,
        )
        process.exitCode = 1
      })
  }
}
