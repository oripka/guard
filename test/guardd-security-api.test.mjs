import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

const waitForListeningUrl = (child) =>
  new Promise((resolve, reject) => {
    let stderr = ''
    const timeout = setTimeout(() => {
      reject(new Error(`guardd did not start:\n${stderr}`))
    }, 10_000)
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

test('guardd exports bounded evidence and only validates policy proposals', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-security-api-'))
  const eventLogPath = path.join(stateDir, 'events.jsonl')
  const event = {
    schemaVersion: 1,
    telemetryVersion: 1,
    eventId: 'evt_fixture',
    runId: 'run_fixture',
    sequence: 1,
    parentEventId: '',
    at: '2026-01-01T00:00:00.000Z',
    type: 'network.flow',
    pid: 42,
    host: 'private.example',
    bytesSent: 128,
    result: 'deny',
  }
  fs.writeFileSync(eventLogPath, `${JSON.stringify(event)}\n`, { mode: 0o600 })

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
    env: {
      ...process.env,
      GUARD_STATE_DIR: stateDir,
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM')
      await new Promise((resolve) => child.once('exit', resolve))
    }
    fs.rmSync(stateDir, { recursive: true, force: true })
  })

  const baseUrl = await waitForListeningUrl(child)
  const headers = { authorization: 'Bearer fixture-token' }
  const evidenceResponse = await fetch(
    `${baseUrl}/security/evidence-windows?privacy=pseudonymous`,
    { headers },
  )
  assert.equal(evidenceResponse.status, 200)
  const evidence = await evidenceResponse.json()
  assert.equal(evidence.sourceEventCount, 1)
  assert.equal(evidence.windows.length, 1)
  assert.match(evidence.windows[0].destinations[0], /^host_[0-9a-f]{16}$/)

  const proposalResponse = await fetch(`${baseUrl}/security/proposals/validate`, {
    method: 'POST',
    headers: {
      ...headers,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      schemaVersion: 1,
      operation: 'add',
      field: 'network.deniedDomains',
      value: 'private.example',
      profile: 'guard',
      evidenceEventIds: ['evt_fixture'],
      rationale: 'Observed denied destination.',
    }),
  })
  assert.equal(proposalResponse.status, 200)
  const proposal = await proposalResponse.json()
  assert.equal(proposal.ok, true)
  assert.equal(proposal.value.requiresHumanApproval, true)
  assert.equal(Object.hasOwn(proposal, 'applied'), false)
})
