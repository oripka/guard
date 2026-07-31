import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildEvidenceWindows,
  createTelemetryContext,
  projectSecurityEvent,
  redactProcessArguments,
  validatePolicyProposal,
  validateSecurityFinding,
} from '../lib/guard-security-telemetry.mjs'

test('process arguments are structured, bounded, and redact credential values', () => {
  const values = redactProcessArguments([
    'node',
    'script.mjs',
    '--api-key',
    'sk-examplecredentialvalue',
    '--password=hunter2',
    'https://alice:secret@example.test/path',
  ])
  assert.equal(values[0].value, 'node')
  assert.equal(values[3].value, '[REDACTED]')
  assert.equal(values[4].value, '--password=[REDACTED]')
  assert.equal(values[5].redacted, true)
  assert.doesNotMatch(values.map((value) => value.value).join(' '), /hunter2|alice:secret/)
})

test('telemetry context assigns stable run identity, ordering, and causal parents', () => {
  let id = 0
  const context = createTelemetryContext({
    runId: 'run_fixture',
    policy: { network: { allowedDomains: ['example.test'] } },
    idFactory: () => `id_${++id}`,
    monotonicClock: () => 42n,
  })
  const started = context.decorate({ type: 'process.started' }, { becomesCausalParent: true })
  const flow = context.decorate({ type: 'network.flow' })
  assert.equal(started.eventId, 'evt_id_1')
  assert.equal(started.sequence, 1)
  assert.equal(flow.sequence, 2)
  assert.equal(flow.parentEventId, started.eventId)
  assert.equal(flow.runId, 'run_fixture')
  assert.match(flow.policySnapshotId, /^policy_[0-9a-f]{20}$/)
})

test('evidence windows correlate events by run and bounded time interval', () => {
  const events = [
    {
      eventId: 'evt_1',
      runId: 'run_1',
      sequence: 1,
      at: '2026-01-01T00:00:01.000Z',
      type: 'sandbox.denial',
      sensitivity: 'ssh-private-key',
      pid: 10,
      result: 'deny',
    },
    {
      eventId: 'evt_2',
      runId: 'run_1',
      sequence: 2,
      at: '2026-01-01T00:01:00.000Z',
      type: 'network.flow',
      host: 'first-seen.example',
      pid: 10,
      bytesSent: 4096,
    },
  ]
  const windows = buildEvidenceWindows(events)
  assert.equal(windows.length, 1)
  assert.deepEqual(windows[0].eventIds, ['evt_1', 'evt_2'])
  assert.deepEqual(windows[0].processIds, [10])
  assert.equal(windows[0].bytesSent, 4096)
  assert.equal(windows[0].deniedCount, 1)
})

test('analysis projection omits raw paths and supports stable pseudonyms', () => {
  const event = {
    eventId: 'evt_1',
    runId: 'run_1',
    at: '2026-01-01T00:00:00.000Z',
    type: 'network.flow',
    projectDir: '/Users/alice/secret-project',
    processPath: '/usr/local/bin/node',
    host: 'private.example',
  }
  const projected = projectSecurityEvent(event, {
    privacy: 'pseudonymous',
    pseudonymSalt: 'fixture',
  })
  assert.match(projected.project, /^project_[0-9a-f]{16}$/)
  assert.match(projected.network.host, /^host_[0-9a-f]{16}$/)
  assert.equal(projected.process.executable, 'node')
  assert.doesNotMatch(JSON.stringify(projected), /secret-project|private\.example/)
})

test('evidence windows accept privacy-projected events', () => {
  const projected = projectSecurityEvent({
    eventId: 'evt_1',
    runId: 'run_1',
    sequence: 1,
    at: '2026-01-01T00:00:00.000Z',
    type: 'network.flow',
    pid: 42,
    host: 'private.example',
    bytesSent: 128,
    bytesReceived: 256,
    result: 'denied',
  }, {
    privacy: 'pseudonymous',
    pseudonymSalt: 'fixture',
  })
  const [window] = buildEvidenceWindows([projected])
  assert.deepEqual(window.processIds, [42])
  assert.match(window.destinations[0], /^host_[0-9a-f]{16}$/)
  assert.equal(window.bytesSent, 128)
  assert.equal(window.bytesReceived, 256)
  assert.equal(window.deniedCount, 1)
})

test('findings require evidence and policy proposals reject broad allows', () => {
  const finding = validateSecurityFinding({
    schemaVersion: 1,
    severity: 'high',
    confidence: 0.9,
    title: 'Suspicious lifecycle process',
    eventIds: ['evt_1'],
    observations: ['A lifecycle script spawned an unexpected shell.'],
  }, ['evt_1'])
  assert.equal(finding.ok, true)

  const broad = validatePolicyProposal({
    schemaVersion: 1,
    operation: 'add',
    field: 'network.allowedDomains',
    value: '*',
    evidenceEventIds: ['evt_1'],
  }, ['evt_1'])
  assert.equal(broad.ok, false)
  assert.match(broad.errors.join(' '), /broad/)

  const narrow = validatePolicyProposal({
    schemaVersion: 1,
    operation: 'add',
    field: 'network.deniedDomains',
    value: 'suspicious.example',
    profile: 'node-app',
    evidenceEventIds: ['evt_1'],
    rationale: 'First-seen destination from a lifecycle process.',
  }, ['evt_1'])
  assert.equal(narrow.ok, true)
  assert.equal(narrow.value.requiresHumanApproval, true)

  const unknownEvidence = validatePolicyProposal({
    schemaVersion: 1,
    operation: 'add',
    field: 'network.deniedDomains',
    value: 'suspicious.example',
    evidenceEventIds: ['evt_missing'],
  }, [])
  assert.equal(unknownEvidence.ok, false)
  assert.match(unknownEvidence.errors.join(' '), /unknown/)

  const relativeFilesystemPath = validatePolicyProposal({
    schemaVersion: 1,
    operation: 'add',
    field: 'filesystem.allowRead',
    value: '.ssh',
    evidenceEventIds: ['evt_1'],
  }, ['evt_1'])
  assert.equal(relativeFilesystemPath.ok, false)
  assert.match(relativeFilesystemPath.errors.join(' '), /absolute path/)

  const malformedHttpRule = validatePolicyProposal({
    schemaVersion: 1,
    operation: 'add',
    field: 'network.httpRules',
    value: { host: 'https://example.test', method: 'get', path: 'v1/data' },
    evidenceEventIds: ['evt_1'],
  }, ['evt_1'])
  assert.equal(malformedHttpRule.ok, false)
  assert.match(malformedHttpRule.errors.join(' '), /host scope|uppercase|start with/)
})
