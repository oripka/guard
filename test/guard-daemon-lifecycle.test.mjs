import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import test from 'node:test'

const waitFor = async (predicate, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const value = await predicate()
    if (value) return value
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error('timed out waiting for daemon lifecycle condition')
}

test('daemon CLI forwards termination to guardd', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-daemon-lifecycle-'))
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }))
  const token = 'lifecycle-test-token'
  const child = spawn(process.execPath, [
    path.resolve('lib/guard-cli.mjs'),
    'daemon',
    '--host', '127.0.0.1',
    '--port', '0',
    '--event-log', path.join(stateDir, 'events.jsonl'),
    '--policy-root', stateDir,
    '--api-token', token,
  ], {
    cwd: path.resolve('.'),
    env: { ...process.env, GUARD_SHIM_BYPASS: '1', GUARD_STATE_DIR: stateDir },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
  })

  let stderr = ''
  child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8') })
  const url = await waitFor(() => stderr.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/)?.[1])
  const before = await fetch(`${url}/health`, { headers: { authorization: `Bearer ${token}` } })
  assert.equal(before.status, 200)

  child.kill('SIGTERM')
  await waitFor(() => child.exitCode !== null || child.signalCode !== null)
  await waitFor(async () => {
    try {
      await fetch(`${url}/health`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(100),
      })
      return false
    } catch {
      return true
    }
  })
})
