#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { consumeEnrollmentTokenFile, enrollWindowsCollector } from './enrollment.js'
import { createWindowsCollectorRuntime, loadWindowsCollectorConfig } from './collector-runtime.js'

const required = (name: string) => { const value = process.env[name]?.trim(); if (!value) throw new Error(`${name} is required`); return value }
const positive = (name: string) => { const value = Number(required(name)); if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`); return value }
export async function main(argv = process.argv.slice(2)) {
  const command = argv[0]
  if (command === 'enroll') {
    const tokenFile = process.env.COLLECTOR_ENROLLMENT_TOKEN_FILE?.trim(); const token = process.env.COLLECTOR_ENROLLMENT_TOKEN?.trim() || (tokenFile ? (await readFile(tokenFile, 'utf8')).trim() : '')
    if (!token) throw new Error('COLLECTOR_ENROLLMENT_TOKEN or COLLECTOR_ENROLLMENT_TOKEN_FILE is required')
    const identity = await enrollWindowsCollector({ controlPlaneUrl: required('COLLECTOR_CONTROL_PLANE_URL'), orgId: positive('COLLECTOR_ORG_ID'), integrationId: positive('COLLECTOR_INTEGRATION_ID'), enrollmentToken: token, stateDirectory: required('COLLECTOR_STATE_DIRECTORY') })
    await consumeEnrollmentTokenFile(tokenFile); process.stdout.write(`${JSON.stringify({ collectorId: identity.collectorId, integrationId: identity.integrationId, enrolled: true })}\n`); return
  }
  if (command === 'run' || command === 'once' || command === 'validate') { const runtime = await createWindowsCollectorRuntime(await loadWindowsCollectorConfig(argv[1] ?? required('COLLECTOR_CONFIG_FILE'))); if (command === 'validate') process.stdout.write(`${JSON.stringify(await runtime.validate())}\n`); else if (command === 'once') { const result = await runtime.collectOnce(); await runtime.flush(); process.stdout.write(`${JSON.stringify(result)}\n`) } else { const controller = new AbortController(); process.once('SIGINT', () => controller.abort()); process.once('SIGTERM', () => controller.abort()); await runtime.run(controller.signal) }; return }
  throw new Error('Usage: cloudverse-windows-collector <enroll|validate|once|run> [config.json]')
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) main().catch((error) => { process.stderr.write(`Collector failed: ${error instanceof Error ? error.message : 'unknown error'}\n`); process.exitCode = 1 })
