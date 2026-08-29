import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

const waitForListeningUrl = (child) => new Promise((resolve, reject) => {
  let stderr = ''
  const timeout = setTimeout(() => reject(new Error(`guardd did not start:\n${stderr}`)), 10_000)
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk) => {
    stderr += chunk
    const match = stderr.match(/listening on (http:\/\/[^\s]+)/)
    if (!match) return
    clearTimeout(timeout)
    resolve(match[1])
  })
  child.once('exit', (code, signal) => {
    clearTimeout(timeout)
    reject(new Error(`guardd exited before listening (${code ?? signal}):\n${stderr}`))
  })
})

test('guardd exposes normalized account state, manual refresh, and redacted login preview', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardd-accounts-'))
  const stateDir = path.join(root, 'state')
  const configRoot = path.join(root, 'config')
  const configDir = path.join(configRoot, 'guard')
  fs.mkdirSync(configDir, { recursive: true })
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
    codeRoot: '/preserved',
    accountMonitoring: {
      schemaVersion: 1,
      passiveIntervalSeconds: 60,
      monitors: [{
        id: 'fixture',
        label: 'Fixture Account',
        providerLabel: 'Fixture Provider',
        target: { type: 'host', environment: { SAFE_PATH: '/fixture' } },
        status: { cadence: 'manual', probe: { type: 'command', argv: ['/usr/bin/true'] } },
        activity: [],
        login: { presentation: 'terminal', argv: ['/usr/bin/true'], environment: { LOGIN_MODE: 'device' } },
      }],
    },
  }), { mode: 0o600 })
  const eventLogPath = path.join(stateDir, 'events.jsonl')
  const child = spawn(process.execPath, [
    path.resolve('daemon/guardd.mjs'),
    '--host', '127.0.0.1',
    '--port', '0',
    '--event-log', eventLogPath,
    '--policy-root', stateDir,
    '--repo-root', process.cwd(),
    '--api-token', 'fixture-token',
  ], {
    cwd: process.cwd(),
    env: { ...process.env, HOME: root, XDG_CONFIG_HOME: configRoot, GUARD_STATE_DIR: stateDir },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM')
      await new Promise((resolve) => child.once('exit', resolve))
    }
    fs.rmSync(root, { recursive: true, force: true })
  })

  const baseUrl = await waitForListeningUrl(child)
  const headers = { authorization: 'Bearer fixture-token' }
  const unauthorized = await fetch(`${baseUrl}/accounts`)
  assert.equal(unauthorized.status, 401)
  const beforeResponse = await fetch(`${baseUrl}/accounts`, { headers })
  assert.equal(beforeResponse.status, 200)
  const before = await beforeResponse.json()
  assert.equal(before.accounts.length, 1)
  assert.equal(before.accounts[0].id, 'fixture')
  assert.equal(before.accounts[0].state, 'unknown')

  const refreshResponse = await fetch(`${baseUrl}/accounts/fixture/refresh`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: '{}',
  })
  assert.equal(refreshResponse.status, 200)
  const refreshed = await refreshResponse.json()
  assert.equal(refreshed.account.state, 'signedIn')

  const previewResponse = await fetch(`${baseUrl}/accounts/fixture/login-preview`, { headers })
  assert.equal(previewResponse.status, 200)
  const preview = await previewResponse.json()
  assert.deepEqual(preview.preview.argv, ['/usr/bin/true'])
  assert.deepEqual(preview.preview.environmentKeys, ['LOGIN_MODE', 'SAFE_PATH'])
  assert.equal(JSON.stringify(preview).includes('/fixture'), false)
  assert.equal(JSON.stringify(preview).includes('device'), false)

  const eventLines = fs.readFileSync(eventLogPath, 'utf8').trim().split('\n').map(JSON.parse)
  assert.ok(eventLines.some((event) => event.type === 'account.session.changed'))
})
