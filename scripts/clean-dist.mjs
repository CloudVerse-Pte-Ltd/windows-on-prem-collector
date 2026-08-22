import { rmSync } from 'node:fs'

// The target is resolved from this checked-in script, never from user input.
rmSync(new URL('../dist', import.meta.url), { recursive: true, force: true })
