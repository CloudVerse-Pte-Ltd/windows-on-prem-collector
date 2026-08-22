import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { redactWindowsCollectorError } from '../security/redaction.js'

export interface CollectorRuntimeHealth {
  schemaVersion: '1.0'
  status: 'STARTING' | 'HEALTHY' | 'DEGRADED'
  updatedAt: string
  consecutiveCollectionFailures: number
  collectionGapStartedAt: string | null
  lastCollectionAttemptAt: string | null
  lastCollectionSuccessAt: string | null
  nextCollectionAttemptAt: string | null
  lastError: string | null
  lastRecoveredCollectionGap: { startedAt: string; recoveredAt: string; failedAttempts: number } | null
}

export const initialRuntimeHealth = (now: Date): CollectorRuntimeHealth => ({
  schemaVersion: '1.0', status: 'STARTING', updatedAt: now.toISOString(), consecutiveCollectionFailures: 0,
  collectionGapStartedAt: null, lastCollectionAttemptAt: null, lastCollectionSuccessAt: null,
  nextCollectionAttemptAt: null, lastError: null, lastRecoveredCollectionGap: null,
})

export function collectionFailureHealth(previous: CollectorRuntimeHealth, attemptedAt: Date, nextAttemptAt: Date, error: unknown): CollectorRuntimeHealth {
  return { ...previous, status: 'DEGRADED', updatedAt: attemptedAt.toISOString(), consecutiveCollectionFailures: previous.consecutiveCollectionFailures + 1,
    collectionGapStartedAt: previous.collectionGapStartedAt ?? attemptedAt.toISOString(), lastCollectionAttemptAt: attemptedAt.toISOString(),
    nextCollectionAttemptAt: nextAttemptAt.toISOString(), lastError: redactWindowsCollectorError(error) }
}

export function collectionSuccessHealth(previous: CollectorRuntimeHealth, collectedAt: Date): CollectorRuntimeHealth {
  return { ...previous, status: 'HEALTHY', updatedAt: collectedAt.toISOString(), consecutiveCollectionFailures: 0,
    collectionGapStartedAt: null, lastCollectionAttemptAt: collectedAt.toISOString(), lastCollectionSuccessAt: collectedAt.toISOString(),
    nextCollectionAttemptAt: null, lastError: null,
    lastRecoveredCollectionGap: previous.collectionGapStartedAt ? { startedAt: previous.collectionGapStartedAt, recoveredAt: collectedAt.toISOString(), failedAttempts: previous.consecutiveCollectionFailures } : previous.lastRecoveredCollectionGap }
}

export class RuntimeHealthStore {
  readonly path: string
  constructor(stateDirectory: string) { this.path = join(stateDirectory, 'runtime-health.json') }
  async read(): Promise<CollectorRuntimeHealth | undefined> {
    let parsed: unknown
    try { parsed = JSON.parse(await readFile(this.path, 'utf8')) } catch (error: any) { if (error?.code === 'ENOENT') return undefined; throw error }
    if (!parsed || typeof parsed !== 'object') throw new Error('Runtime health state is invalid')
    const value = parsed as Partial<CollectorRuntimeHealth>
    if (value.schemaVersion !== '1.0' || !['STARTING', 'HEALTHY', 'DEGRADED'].includes(value.status ?? '') || !Number.isSafeInteger(value.consecutiveCollectionFailures) || (value.consecutiveCollectionFailures ?? -1) < 0) throw new Error('Runtime health state is invalid')
    return value as CollectorRuntimeHealth
  }
  async write(value: CollectorRuntimeHealth) {
    await mkdir(dirname(this.path), { recursive: true })
    const temporary = `${this.path}.${randomUUID()}.tmp`
    await writeFile(temporary, JSON.stringify(value), { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    await rename(temporary, this.path)
  }
}
