import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
  AccountMonitorStore,
  accountSnapshotChanged,
  buildDefaultAccountMonitoringConfig,
  buildTargetCommand,
  inspectAccountConfigTrust,
  loginPreview,
  runAccountMonitor,
  validateAccountMonitoringConfig,
} from '../lib/guard-account-monitor.mjs'

const tempRoot = (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-account-monitor-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}

test('default account monitor configuration is provider data, not provider code', () => {
  const validation = validateAccountMonitoringConfig(buildDefaultAccountMonitoringConfig({
    home: '/Users/tester',
    awsStartUrl: 'https://example.awsapps.com/start',
    packetsafariWebsiteDir: '/Users/tester/code/packetsafari-website',
  }))
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.config.monitors.length, 5)
  assert.equal(validation.config.monitors.find((item) => item.id === 'cloudflare-wrangler').status.cadence, 'manual')
  assert.ok(validation.warnings.some((warning) => warning.includes('explicitly invokes a shell')))
})

test('validation rejects duplicate ids, string commands, credential flags, and malformed pointers', () => {
  const result = validateAccountMonitoringConfig({
    schemaVersion: 1,
    passiveIntervalSeconds: 1,
    monitors: [
      {
        id: 'duplicate',
        target: { type: 'host' },
        status: {
          probe: { type: 'command', argv: 'unsafe shell text' },
          extract: { expiresAt: { source: 'json', pointer: 'not-a-pointer' } },
        },
        login: {
          argv: ['/bin/tool', '--api-key=secret'],
          environment: { ACCESS_TOKEN: 'also-secret' },
        },
      },
      {
        id: 'duplicate',
        target: { type: 'remote-magic' },
        status: { probe: { type: 'command', argv: ['/bin/true'] } },
      },
    ],
  })
  assert.ok(result.errors.some((entry) => entry.includes('duplicated')))
  assert.ok(result.errors.some((entry) => entry.includes('non-empty string array')))
  assert.ok(result.errors.some((entry) => entry.includes('credential-bearing')))
  assert.ok(result.errors.some((entry) => entry.includes('login.environment')))
  assert.ok(result.errors.some((entry) => entry.includes('JSON Pointer')))
  assert.ok(result.errors.some((entry) => entry.includes('passiveIntervalSeconds')))
  assert.ok(result.errors.some((entry) => entry.includes('host or docker')))
})

test('trusted executable config must be user-owned and not writable by group or world', (t) => {
  const root = tempRoot(t)
  const target = path.join(root, 'config.json')
  fs.writeFileSync(target, '{}', { mode: 0o600 })
  assert.equal(inspectAccountConfigTrust(target).trusted, true)
  fs.chmodSync(target, 0o622)
  assert.deepEqual(inspectAccountConfigTrust(target).reason, 'group-or-world-writable')
})

test('command probe normalizes fields and does not retain unrelated output', async () => {
  const raw = {
    schemaVersion: 1,
    monitors: [{
      id: 'fixture',
      label: 'Fixture',
      target: { type: 'host' },
      status: {
        probe: {
          type: 'command',
          argv: ['/usr/bin/printf', '{"state":"ok","identity":"person@example.test","expiresAt":"2099-01-01T00:00:00Z","token":"must-not-persist"}'],
          parseJson: true,
        },
        stateRules: [{ pointer: '/state', equals: 'ok', state: 'signedIn' }],
        extract: {
          identity: { source: 'json', pointer: '/identity' },
          expiresAt: { source: 'json', pointer: '/expiresAt' },
        },
      },
      activity: [],
    }],
  }
  const { config } = validateAccountMonitoringConfig(raw)
  const snapshot = await runAccountMonitor({ monitor: config.monitors[0] })
  assert.equal(snapshot.state, 'signedIn')
  assert.equal(snapshot.identity, 'person@example.test')
  assert.equal(snapshot.expiresAt, '2099-01-01T00:00:00.000Z')
  assert.equal(JSON.stringify(snapshot).includes('must-not-persist'), false)
})

test('command probes preserve terminal context required by native CLIs', async () => {
  const { config } = validateAccountMonitoringConfig({
    schemaVersion: 1,
    monitors: [{
      id: 'terminal-context',
      target: { type: 'host' },
      status: {
        probe: { type: 'command', argv: ['/usr/bin/printenv', 'TERM'] },
        stateRules: [{ exitCode: 0, stdoutMatches: '^fixture-terminal$', flags: 'm', state: 'signedIn' }],
      },
      activity: [],
    }],
  })
  const snapshot = await runAccountMonitor({
    monitor: config.monitors[0],
    env: { HOME: '/tmp', PATH: '/usr/bin:/bin', TERM: 'fixture-terminal' },
  })
  assert.equal(snapshot.state, 'signedIn')

  config.monitors[0].status.stateRules[0].stdoutMatches = '^dumb$'
  const fallback = await runAccountMonitor({
    monitor: config.monitors[0],
    env: { HOME: '/tmp', PATH: '/usr/bin:/bin' },
  })
  assert.equal(fallback.state, 'signedIn')
})

test('command probes enforce timeout and a combined output cap', async () => {
  const validation = validateAccountMonitoringConfig({
    schemaVersion: 1,
    monitors: [
      {
        id: 'truncated',
        target: { type: 'host' },
        status: {
          probe: {
            type: 'command',
            argv: ['/usr/bin/seq', '1', '10000'],
            maxOutputBytes: 1024,
          },
        },
      },
      {
        id: 'timeout',
        target: { type: 'host' },
        status: {
          probe: {
            type: 'command',
            argv: ['/bin/sleep', '2'],
            timeoutMs: 100,
          },
        },
      },
    ],
  })
  assert.deepEqual(validation.errors, [])
  const truncated = await runAccountMonitor({ monitor: validation.config.monitors[0] })
  const timedOut = await runAccountMonitor({ monitor: validation.config.monitors[1] })
  assert.equal(truncated.reasonCode, 'probe-output-truncated')
  assert.equal(timedOut.reasonCode, 'probe-timeout')
})

test('JSON cache expiry and latest file activity remain distinct from checked time', async (t) => {
  const root = tempRoot(t)
  const cacheDir = path.join(root, 'sso')
  const activityDir = path.join(root, 'activity')
  fs.mkdirSync(cacheDir)
  fs.mkdirSync(activityDir)
  fs.writeFileSync(path.join(cacheDir, 'session.json'), JSON.stringify({ portal: 'one', expiresAt: '2099-02-03T04:05:06Z', accessToken: 'never-return' }))
  const activityPath = path.join(activityDir, 'used.json')
  fs.writeFileSync(activityPath, '{}')
  const usedAt = new Date('2026-08-20T10:00:00Z')
  fs.utimesSync(activityPath, usedAt, usedAt)
  const { config } = validateAccountMonitoringConfig({
    schemaVersion: 1,
    monitors: [{
      id: 'files',
      target: { type: 'host' },
      status: {
        probe: { type: 'jsonFiles', paths: [path.join(cacheDir, '*.json')], match: { '/portal': 'one' } },
        extract: { expiresAt: { source: 'json', pointer: '/expiresAt' } },
      },
      activity: [{ type: 'latestMtime', paths: [path.join(activityDir, '*.json')], sourceLabel: 'local activity' }],
    }],
  })
  const snapshot = await runAccountMonitor({ monitor: config.monitors[0], now: new Date('2026-08-25T00:00:00Z') })
  assert.equal(snapshot.state, 'signedIn')
  assert.equal(snapshot.lastUsedAt, usedAt.toISOString())
  assert.equal(snapshot.lastUsedSource, 'local activity')
  assert.notEqual(snapshot.lastUsedAt, snapshot.checkedAt)
  assert.equal(JSON.stringify(snapshot).includes('never-return'), false)
})

test('manual probes are not executed by passive refresh', async () => {
  const { config } = validateAccountMonitoringConfig({
    schemaVersion: 1,
    monitors: [{
      id: 'manual',
      target: { type: 'host' },
      status: { cadence: 'manual', probe: { type: 'command', argv: ['/usr/bin/false'] } },
      activity: [],
    }],
  })
  const snapshot = await runAccountMonitor({ monitor: config.monitors[0], mode: 'passive' })
  assert.equal(snapshot.state, 'unknown')
  assert.equal(snapshot.reasonCode, 'manual-probe-not-run')
  assert.equal(snapshot.stale, true)
})

test('Docker targets assemble explicit noninteractive and interactive argv', () => {
  const target = {
    type: 'docker',
    label: 'Worker',
    dockerPath: '/usr/local/bin/docker',
    container: 'worker',
    user: '4242:4141',
    environment: { CODEX_HOME: '/runtime/codex' },
  }
  const status = buildTargetCommand({ target, argv: ['/usr/local/bin/codex', 'login', 'status'] })
  assert.deepEqual(status.args, ['exec', '--user', '4242:4141', '-e', 'CODEX_HOME=/runtime/codex', 'worker', '/usr/local/bin/codex', 'login', 'status'])
  const login = buildTargetCommand({ target, argv: ['/usr/local/bin/codex', 'login'], interactive: true })
  assert.equal(login.args[1], '-it')
  const preview = loginPreview({
    id: 'worker',
    label: 'Worker',
    providerLabel: 'Fixture',
    target,
    login: { presentation: 'terminal', argv: ['/usr/local/bin/codex', 'login'] },
  })
  assert.ok(preview.argv.includes('CODEX_HOME=<redacted>'))
  assert.equal(preview.argv.includes('CODEX_HOME=/runtime/codex'), false)
})

test('stopped Docker targets become actionable unavailable snapshots', async (t) => {
  const root = tempRoot(t)
  const dockerFixture = path.join(root, 'docker-fixture')
  fs.writeFileSync(dockerFixture, '#!/bin/sh\nprintf "Error: No such container: worker\\n" >&2\nexit 1\n', { mode: 0o700 })
  const validation = validateAccountMonitoringConfig({
    schemaVersion: 1,
    monitors: [{
      id: 'docker-unavailable',
      target: { type: 'docker', dockerPath: dockerFixture, container: 'worker' },
      status: { probe: { type: 'command', argv: ['/usr/bin/true'] } },
      activity: [],
    }],
  })
  assert.deepEqual(validation.errors, [])
  const snapshot = await runAccountMonitor({ monitor: validation.config.monitors[0] })
  assert.equal(snapshot.state, 'unavailable')
  assert.equal(snapshot.reasonCode, 'docker-target-unavailable')
})

test('store persists normalized state privately and emits only transitions', async (t) => {
  const root = tempRoot(t)
  const configDir = path.join(root, 'config', 'guard')
  const stateDir = path.join(root, 'state')
  fs.mkdirSync(configDir, { recursive: true })
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
    accountMonitoring: {
      schemaVersion: 1,
      monitors: [{
        id: 'stable',
        target: { type: 'host' },
        status: { probe: { type: 'command', argv: ['/usr/bin/true'] } },
        activity: [],
      }],
    },
  }), { mode: 0o600 })
  const eventLogPath = path.join(stateDir, 'events.jsonl')
  const store = new AccountMonitorStore({
    stateDir,
    eventLogPath,
    env: { ...process.env, HOME: root, XDG_CONFIG_HOME: path.join(root, 'config') },
  })
  await store.refresh({ mode: 'passive' })
  await store.refresh({ mode: 'passive' })
  const lines = fs.readFileSync(eventLogPath, 'utf8').trim().split('\n')
  assert.equal(lines.length, 1)
  assert.equal(JSON.parse(lines[0]).type, 'account.session.changed')
  const statePath = path.join(stateDir, 'account-sessions.json')
  assert.equal(fs.statSync(statePath).mode & 0o777, 0o600)
})

test('account session events ignore check and local activity churn', () => {
  const before = { state: 'signedIn', identity: 'fixture', expiresAt: '2099-01-01T00:00:00.000Z', lastUsedAt: '2026-01-01T00:00:00.000Z', reasonCode: 'one' }
  assert.equal(accountSnapshotChanged(before, { ...before, lastUsedAt: '2026-02-01T00:00:00.000Z', reasonCode: 'two' }), false)
  assert.equal(accountSnapshotChanged(before, { ...before, expiresAt: '2099-02-01T00:00:00.000Z' }), true)
})

test('daemon-free CLI login uses terminal execution and refreshes normalized status', (t) => {
  const root = tempRoot(t)
  const configDir = path.join(root, 'config', 'guard')
  const stateDir = path.join(root, 'state')
  fs.mkdirSync(configDir, { recursive: true })
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
    accountMonitoring: {
      schemaVersion: 1,
      monitors: [{
        id: 'login-fixture',
        target: { type: 'host' },
        status: { probe: { type: 'command', argv: ['/usr/bin/true'] } },
        activity: [],
        login: { presentation: 'terminal', argv: ['/usr/bin/true'] },
      }],
    },
  }), { mode: 0o600 })
  const result = spawnSync(path.resolve('bin/guard'), ['account', 'login', 'login-fixture'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: root,
      XDG_CONFIG_HOME: path.join(root, 'config'),
      GUARD_STATE_DIR: stateDir,
      GUARD_REAL_NODE: process.execPath,
    },
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
  const snapshot = JSON.parse(fs.readFileSync(path.join(stateDir, 'account-sessions.json'), 'utf8')).snapshots['login-fixture']
  assert.equal(snapshot.state, 'signedIn')
  const eventTypes = fs.readFileSync(path.join(stateDir, 'events.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line).type)
  assert.deepEqual(eventTypes, ['account.login.started', 'account.login.completed', 'account.session.changed'])
})
