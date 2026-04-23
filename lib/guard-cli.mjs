#!/usr/bin/env node

import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { main } from './guard-launcher.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const repoRoot = path.resolve(path.dirname(scriptPath), '..')
const invokedPath = process.env.GUARD_INVOKED_PATH || process.argv[1] || path.resolve(repoRoot, 'bin/guard')

await main({
  argv: process.argv.slice(2),
  invokedPath,
  repoRoot,
})
