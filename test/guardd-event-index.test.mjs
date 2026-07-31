import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { EventIndex, EventTail } from '../daemon/guardd.mjs'

test('event index rebuild persists once and can be reused at startup', (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-event-index-'))
  const eventLogPath = path.join(stateDir, 'events.jsonl')
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }))
  const events = Array.from({ length: 250 }, (_, index) => ({
    schemaVersion: 1,
    at: new Date(1_700_000_000_000 + index).toISOString(),
    type: index % 2 === 0 ? 'network.flow' : 'sandbox.denial',
    host: index % 2 === 0 ? 'example.test' : '',
    profile: 'guard',
    result: index % 2 === 0 ? 'allow' : 'deny',
  }))
  fs.writeFileSync(eventLogPath, `${events.map(JSON.stringify).join('\n')}\n`)

  const index = new EventIndex({ stateDir })
  let persistCount = 0
  const persist = index.persist.bind(index)
  index.persist = () => {
    persistCount += 1
    persist()
  }
  index.rebuildFromLog(eventLogPath)

  assert.equal(persistCount, 1)
  assert.equal(index.totalEvents, 250)
  assert.equal(index.byType['network.flow'], 125)
  assert.equal(index.byType['sandbox.denial'], 125)

  const restored = new EventIndex({ stateDir })
  assert.equal(restored.load(), true)
  assert.equal(restored.totalEvents, 250)
  assert.deepEqual(restored.byType, index.byType)
})

test('event tail automatically compacts oversized logs on complete lines', (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-event-retention-'))
  const eventLogPath = path.join(stateDir, 'events.jsonl')
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }))
  const events = Array.from({ length: 100 }, (_, index) => ({
    schemaVersion: 1,
    at: new Date(1_700_000_000_000 + index).toISOString(),
    type: 'network.flow',
    host: `host-${index}.example.test`,
    profile: 'guard',
    result: 'allow',
  }))
  fs.writeFileSync(eventLogPath, `${events.map(JSON.stringify).join('\n')}\n`)
  const beforeBytes = fs.statSync(eventLogPath).size

  const tail = new EventTail({
    eventLogPath,
    stateDir,
    maxEvents: 500,
    pollMs: 60_000,
    eventLogMaxBytes: 4096,
    eventLogRetainBytes: 2048,
  })
  tail.start()
  tail.stop()

  const contents = fs.readFileSync(eventLogPath, 'utf8')
  const retained = contents.trim().split('\n').map((line) => JSON.parse(line))
  assert.ok(fs.statSync(eventLogPath).size < 4096)
  assert.ok(beforeBytes > 4096)
  assert.ok(retained[0].host !== 'host-0.example.test')
  assert.equal(retained.at(-1).type, 'daemon.log.truncated')
  assert.equal(retained.at(-1).operation, 'automatic-retention')
  assert.equal(tail.index.totalEvents, retained.length)
  assert.equal(tail.retention.truncated, true)

  const restored = new EventTail({
    eventLogPath,
    stateDir,
    maxEvents: 500,
    pollMs: 60_000,
    eventLogMaxBytes: 4096,
    eventLogRetainBytes: 2048,
  })
  restored.start()
  restored.stop()
  assert.equal(restored.retention.truncated, true)
  assert.equal(restored.retention.lastTruncation.operation, 'automatic-retention')
  assert.equal(restored.retention.lastTruncation.beforeBytes, beforeBytes)
})
