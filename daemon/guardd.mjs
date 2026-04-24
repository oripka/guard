#!/usr/bin/env node
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { URL } from 'node:url'
import {
  buildPolicySnapshot,
  MUTABLE_PROFILE_ARRAY_FIELDS,
  evaluateNetworkPolicy,
  loadProfileConfig,
  mergeProfileConfig,
  mutateArrayRuleConfig,
  mutateHttpRuleConfig,
  mutateTlsConfig,
  profileVersion,
  profileVersionInfo,
  readJsonFile,
  writeJsonFile,
} from '../lib/guard-policy.mjs'

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 8765
const DEFAULT_MAX_EVENTS = 500
const DEFAULT_POLL_MS = 1000
const DEFAULT_REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const GUARDD_API_VERSION = 1
const EVENT_LOG_SCHEMA_VERSION = 1
const EVENT_STORAGE_SCHEMA_VERSION = 2
const EVENT_INDEX_SCHEMA_VERSION = 2
const DEFAULT_LOG_TRUNCATE_MAX_BYTES = 1024 * 1024
const DEFAULT_RECOVERY_TAIL_BYTES = 1024 * 1024
const DEFAULT_EVENT_QUERY_MAX_BYTES = 5 * 1024 * 1024
const EXTENSION_SYNC_VERSION = 1
const DEFAULT_ALERT_TIMEOUT_MS = 120 * 1000
const MAX_ALERT_TIMEOUT_MS = 24 * 60 * 60 * 1000
const DEFAULT_KEYCHAIN_TOKEN_SERVICE = 'com.guard.guardd.api-token'
const DEFAULT_KEYCHAIN_TOKEN_ACCOUNT = os.userInfo().username || 'guardd'

const expandHome = (value) => {
  if (!value || value === '~') return value === '~' ? os.homedir() : value
  return value.startsWith('~/') ? path.join(os.homedir(), value.slice(2)) : value
}

const resolveGuardStateDir = (env = process.env) => {
  if (env.GUARD_STATE_DIR) return path.resolve(expandHome(env.GUARD_STATE_DIR))
  if (env.HOME) return path.join(env.HOME, 'Library', 'Application Support', 'guard')
  return path.resolve('/tmp/guard-state')
}

const resolveGuardEventLogPath = (env = process.env) => {
  if (env.GUARD_EVENT_LOG) return path.resolve(expandHome(env.GUARD_EVENT_LOG))
  return path.join(resolveGuardStateDir(env), 'events.jsonl')
}

const resolveGuardPolicyRoot = (env = process.env, stateDir = resolveGuardStateDir(env)) => {
  if (env.GUARDD_POLICY_ROOT) return path.resolve(expandHome(env.GUARDD_POLICY_ROOT))
  if (env.GUARD_PROJECT_DIR) return path.resolve(expandHome(env.GUARD_PROJECT_DIR))
  return stateDir
}

const parsePositiveInt = (value, fallback) => {
  if (value === undefined || value === null || value === '') return fallback
  const parsed = Number.parseInt(String(value), 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

const parsePort = (value, fallback) => {
  if (value === undefined || value === null || value === '') return fallback
  const parsed = Number.parseInt(String(value), 10)
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 65535 ? parsed : fallback
}

const parseArgs = (argv, env = process.env) => {
  const stateDir = resolveGuardStateDir(env)
  const config = {
    host: env.GUARDD_HOST || DEFAULT_HOST,
    port: parsePort(env.GUARDD_PORT, DEFAULT_PORT),
    stateDir,
    eventLogPath: resolveGuardEventLogPath(env),
    maxEvents: parsePositiveInt(env.GUARDD_MAX_EVENTS, DEFAULT_MAX_EVENTS),
    pollMs: parsePositiveInt(env.GUARDD_POLL_MS, DEFAULT_POLL_MS),
    policyRoot: resolveGuardPolicyRoot(env, stateDir),
    repoRoot: path.resolve(expandHome(env.GUARDD_REPO_ROOT || DEFAULT_REPO_ROOT)),
    apiToken: env.GUARDD_API_TOKEN || '',
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    const readValue = () => {
      index += 1
      if (index >= argv.length) throw new Error(`${arg} requires a value`)
      return argv[index]
    }

    if (arg === '--host') config.host = readValue()
    else if (arg === '--port') config.port = parsePort(readValue(), config.port)
    else if (arg === '--event-log') config.eventLogPath = path.resolve(expandHome(readValue()))
    else if (arg === '--max-events') config.maxEvents = parsePositiveInt(readValue(), config.maxEvents)
    else if (arg === '--poll-ms') config.pollMs = parsePositiveInt(readValue(), config.pollMs)
    else if (arg === '--policy-root') config.policyRoot = path.resolve(expandHome(readValue()))
    else if (arg === '--repo-root') config.repoRoot = path.resolve(expandHome(readValue()))
    else if (arg === '--api-token') config.apiToken = readValue()
    else if (arg === '--help' || arg === '-h') config.help = true
    else throw new Error(`Unknown option: ${arg}`)
  }

  return config
}

const usage = () => `Usage: node daemon/guardd.mjs [options]

Options:
  --host HOST          Listen host (default: ${DEFAULT_HOST})
  --port PORT          Listen port (default: ${DEFAULT_PORT})
  --event-log PATH     Guard JSONL event log (default: GUARD_EVENT_LOG or state dir)
  --max-events N       Number of parsed events retained in memory (default: ${DEFAULT_MAX_EVENTS})
  --poll-ms N          Event log polling interval in milliseconds (default: ${DEFAULT_POLL_MS})
  --policy-root PATH   Profile root containing .guard/*.json (default: GUARDD_POLICY_ROOT, GUARD_PROJECT_DIR, or Guard state dir)
  --repo-root PATH     Guard repo root for built-in profiles/templates (default: ${DEFAULT_REPO_ROOT})
  --api-token TOKEN    Require a Bearer or X-Guard-Token token for the HTTP API
  -h, --help           Show this help

Endpoints:
  GET /health
  GET /state
  GET /tls/ca
  GET /tls/cert?host=api.example.com
  GET /tls/status
  GET /events?limit=N&type=network.decision
  GET /events/query?limit=N&type=network.decision&host=api.example.com
  GET /events/index
  GET /events/integrity
  GET /alerts?limit=N
  GET /alerts/pending?limit=N
  GET /auth/token
  GET /security/status
  GET /policy?profile=guard
  GET /profiles
  GET /profiles/:name
  GET /templates
  GET /templates/:name
  GET /templates/:name/preview?profile=guard
  POST /policy/evaluate
  POST /extension/sync
  POST /tls/ca
  POST /tls/cert
  POST /alerts/pending
  POST /alerts/decision
  POST /alerts/:id/resolve
  POST /auth/token/rotate
  POST /auth/token/persist
  POST /profiles/:name/rules
  POST /profiles/:name/tls
  POST /events/truncate
  POST /templates/:name/preview
  POST /templates/:name/apply
`

const safeReadJsonFile = (target, fallback = null) => {
  try {
    return readJsonFile(target)
  } catch {
    return fallback
  }
}

const statIdentity = (stat) => ({
  dev: Number.isFinite(stat.dev) ? stat.dev : null,
  ino: Number.isFinite(stat.ino) ? stat.ino : null,
  size: stat.size,
  mtimeMs: stat.mtimeMs,
})

const sameFileIdentity = (left = {}, right = {}) => {
  if (left.dev === null || left.ino === null || right.dev === null || right.ino === null) return true
  return left.dev === right.dev && left.ino === right.ino
}

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

const classifyEventLine = (line) => {
  let event
  try {
    event = JSON.parse(line)
  } catch (error) {
    return { event: null, invalidReason: 'json_parse_failed', tamperReason: '', message: error.message }
  }
  if (!isPlainObject(event)) {
    return { event: null, invalidReason: 'json_event_not_object', tamperReason: '', message: '' }
  }
  if (!Number.isInteger(event.schemaVersion)) {
    return { event: null, invalidReason: '', tamperReason: 'missing_schema_version', message: '' }
  }
  if (event.schemaVersion !== EVENT_LOG_SCHEMA_VERSION) {
    return {
      event: null,
      invalidReason: '',
      tamperReason: 'unsupported_schema_version',
      message: `unsupported event schemaVersion ${event.schemaVersion}`,
    }
  }
  return { event, invalidReason: '', tamperReason: '', message: '' }
}

const incrementBucket = (bucket, key) => {
  const normalized = String(key || '').trim() || '(none)'
  bucket[normalized] = (bucket[normalized] || 0) + 1
}

const topBucketEntries = (bucket, limit = 10) =>
  Object.entries(bucket || {})
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }))

class EventIndex {
  constructor({ stateDir }) {
    this.path = path.join(stateDir || resolveGuardStateDir(), 'event-index.json')
    this.reset()
  }

  reset() {
    this.totalEvents = 0
    this.byType = {}
    this.byHost = {}
    this.byProfile = {}
    this.byResult = {}
    this.alertDecisions = 0
    this.lastEventAt = null
    this.updatedAt = null
    this.rebuild = {
      attempted: false,
      completed: false,
      reason: '',
      startedAt: null,
      completedAt: null,
      durationMs: 0,
      eventLogPath: '',
      eventLogIdentity: null,
      scannedBytes: 0,
      scannedLineCount: 0,
      validLineCount: 0,
      invalidLineCount: 0,
      tamperLineCount: 0,
      schemaVersions: {},
    }
  }

  increment(bucket, key) {
    incrementBucket(bucket, key)
  }

  record(event = {}) {
    this.totalEvents += 1
    this.increment(this.byType, event.type)
    this.increment(this.byHost, event.host)
    this.increment(this.byProfile, event.profile)
    const result = event.result || (typeof event.allowed === 'boolean' ? (event.allowed ? 'allow' : 'deny') : '')
    this.increment(this.byResult, result)
    if (event.type === 'guard.alert.decision') this.alertDecisions += 1
    this.lastEventAt = event.at || this.lastEventAt
    this.updatedAt = new Date().toISOString()
    this.persist()
  }

  rebuildFromLog(eventLogPath, { reason = 'startup' } = {}) {
    this.reset()
    const started = Date.now()
    const startedAt = new Date(started).toISOString()
    this.rebuild = {
      ...this.rebuild,
      attempted: true,
      completed: false,
      reason,
      startedAt,
      eventLogPath,
    }
    if (!fileExists(eventLogPath)) {
      const completed = Date.now()
      this.rebuild = {
        ...this.rebuild,
        completed: true,
        completedAt: new Date(completed).toISOString(),
        durationMs: completed - started,
      }
      this.persist()
      return
    }
    const stat = fs.statSync(eventLogPath)
    this.rebuild.eventLogIdentity = statIdentity(stat)
    this.rebuild.scannedBytes = stat.size
    const content = fs.readFileSync(eventLogPath, 'utf8')
    for (const line of content.split(/\r?\n/)) {
      if (!line.trim()) continue
      this.rebuild.scannedLineCount += 1
      let raw
      try {
        raw = JSON.parse(line)
        incrementBucket(this.rebuild.schemaVersions, raw?.schemaVersion)
      } catch {
        incrementBucket(this.rebuild.schemaVersions, 'unparseable')
      }
      const classified = classifyEventLine(line)
      if (classified.invalidReason) {
        this.rebuild.invalidLineCount += 1
        continue
      }
      if (classified.tamperReason) {
        this.rebuild.tamperLineCount += 1
        continue
      }
      this.record(classified.event)
      this.rebuild.validLineCount += 1
    }
    const completed = Date.now()
    this.rebuild = {
      ...this.rebuild,
      completed: true,
      completedAt: new Date(completed).toISOString(),
      durationMs: completed - started,
    }
    this.persist()
  }

  payload() {
    return {
      schemaVersion: EVENT_INDEX_SCHEMA_VERSION,
      eventSchemaVersion: EVENT_LOG_SCHEMA_VERSION,
      path: this.path,
      totalEvents: this.totalEvents,
      alertDecisions: this.alertDecisions,
      lastEventAt: this.lastEventAt,
      updatedAt: this.updatedAt,
      rebuild: this.rebuild,
      integrity: {
        invalidLineCount: this.rebuild.invalidLineCount,
        tamperLineCount: this.rebuild.tamperLineCount,
        validLineCount: this.rebuild.validLineCount,
      },
      summaries: {
        byType: topBucketEntries(this.byType),
        byHost: topBucketEntries(this.byHost),
        byProfile: topBucketEntries(this.byProfile),
        byResult: topBucketEntries(this.byResult),
      },
      byType: this.byType,
      byHost: this.byHost,
      byProfile: this.byProfile,
      byResult: this.byResult,
    }
  }

  persist() {
    try {
      writeJsonFile(this.path, this.payload())
    } catch {}
  }
}

class EventTail {
  constructor({ eventLogPath, maxEvents, pollMs, stateDir }) {
    this.eventLogPath = eventLogPath
    this.maxEvents = maxEvents
    this.pollMs = pollMs
    this.stateDir = stateDir || resolveGuardStateDir()
    this.metadataPath = path.join(this.stateDir, 'daemon-state.json')
    this.index = new EventIndex({ stateDir: this.stateDir })
    this.events = []
    this.offset = 0
    this.partial = ''
    this.timer = null
    this.readError = null
    this.invalidLineCount = 0
    this.tamperLineCount = 0
    this.lastInvalidLine = null
    this.lastTamperLine = null
    this.lastReadAt = null
    this.lastPersistedAt = null
    this.storageMigrations = []
    this.recovery = {
      attempted: false,
      recovered: false,
      mode: 'none',
      unreadBytes: 0,
      recoveredEventCount: 0,
      previousOffset: 0,
      currentOffset: 0,
      metadataPath: this.metadataPath,
      reason: '',
    }
    this.retention = {
      maxEvents,
      recoveryTailBytes: DEFAULT_RECOVERY_TAIL_BYTES,
      truncated: false,
      lastTruncatedAt: null,
      lastTruncation: null,
    }
  }

  start() {
    this.recover()
    this.index.rebuildFromLog(this.eventLogPath, { reason: 'startup' })
    this.poll()
    this.timer = setInterval(() => this.poll(), this.pollMs)
    this.timer.unref?.()
  }

  stop() {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
  }

  poll() {
    let stat
    try {
      stat = fs.statSync(this.eventLogPath)
    } catch (error) {
      if (error.code !== 'ENOENT') this.readError = error.message
      this.persist()
      return
    }

    if (!stat.isFile()) {
      this.readError = 'event log path is not a file'
      this.persist({ stat })
      return
    }

    if (stat.size < this.offset) {
      this.offset = 0
      this.partial = ''
      this.recovery = {
        ...this.recovery,
        mode: 'log-rewritten',
        reason: 'event log is smaller than persisted cursor',
        previousOffset: this.recovery.currentOffset || this.offset,
        currentOffset: 0,
      }
    }
    if (stat.size === this.offset) {
      this.persist({ stat })
      return
    }

    const length = stat.size - this.offset
    const fd = fs.openSync(this.eventLogPath, 'r')
    try {
      const buffer = Buffer.alloc(length)
      fs.readSync(fd, buffer, 0, length, this.offset)
      this.offset = stat.size
      this.consume(buffer.toString('utf8'))
      this.readError = null
      this.lastReadAt = new Date().toISOString()
      this.recovery.currentOffset = this.offset
    } catch (error) {
      this.readError = error.message
    } finally {
      fs.closeSync(fd)
    }
    this.persist({ stat })
  }

  consume(chunk) {
    const lines = `${this.partial}${chunk}`.split(/\r?\n/)
    this.partial = lines.pop() || ''
    for (const line of lines) {
      if (!line.trim()) continue
      const classified = classifyEventLine(line)
      if (classified.invalidReason) {
        this.invalidLineCount += 1
        this.lastInvalidLine = {
          at: new Date().toISOString(),
          reason: classified.invalidReason,
          message: classified.message,
        }
        continue
      }
      if (classified.tamperReason) {
        this.tamperLineCount += 1
        this.lastTamperLine = {
          at: new Date().toISOString(),
          reason: classified.tamperReason,
          message: classified.message,
        }
        continue
      }
      this.push(classified.event)
    }
  }

  push(event) {
    this.events.push(event)
    this.index.record(event)
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents)
    }
  }

  recent({ limit, type }) {
    let events = this.events
    if (type) events = events.filter((event) => event?.type === type)
    return events.slice(-limit).reverse()
  }

  resetAfterLogRewrite({ clearEvents = true } = {}) {
    this.offset = 0
    this.partial = ''
    if (clearEvents) this.events = []
    this.readError = null
    this.lastReadAt = new Date().toISOString()
    this.poll()
  }

  recover() {
    this.recovery = {
      ...this.recovery,
      attempted: true,
      recovered: false,
      mode: 'none',
      unreadBytes: 0,
      recoveredEventCount: 0,
      reason: '',
    }

    const previous = safeReadJsonFile(this.metadataPath, null)
    if (previous?.schemaVersion !== EVENT_STORAGE_SCHEMA_VERSION) {
      this.storageMigrations = [
        {
          from: previous?.schemaVersion || 0,
          to: EVENT_STORAGE_SCHEMA_VERSION,
          appliedAt: new Date().toISOString(),
          reason: 'add durable index rebuild and JSONL integrity metadata',
        },
      ]
    } else if (Array.isArray(previous?.migrations)) {
      this.storageMigrations = previous.migrations
    }
    if (previous?.retention) {
      this.retention = {
        ...this.retention,
        ...previous.retention,
        maxEvents: this.maxEvents,
        recoveryTailBytes: DEFAULT_RECOVERY_TAIL_BYTES,
      }
    }

    let stat
    try {
      stat = fs.statSync(this.eventLogPath)
    } catch (error) {
      this.recovery.reason = error.code === 'ENOENT' ? 'event log does not exist yet' : error.message
      this.persist()
      return
    }

    if (!stat.isFile()) {
      this.readError = 'event log path is not a file'
      this.recovery.reason = this.readError
      this.persist({ stat })
      return
    }

    const identity = statIdentity(stat)
    const cursor = previous?.cursor || {}
    const previousIdentity = cursor.identity || {}
    const samePath = cursor.eventLogPath === this.eventLogPath
    const usableCursor = samePath
      && Number.isInteger(cursor.offset)
      && cursor.offset >= 0
      && cursor.offset <= stat.size
      && sameFileIdentity(previousIdentity, identity)

    if (usableCursor) {
      this.offset = cursor.offset
      this.partial = typeof cursor.partial === 'string' ? cursor.partial : ''
      this.recovery = {
        ...this.recovery,
        recovered: true,
        mode: 'cursor',
        unreadBytes: stat.size - cursor.offset,
        previousOffset: cursor.offset,
        currentOffset: this.offset,
        previousReadAt: previous?.tail?.lastReadAt || null,
      }
      this.recoverRecentEvents({ stat, endOffset: cursor.offset })
      this.persist({ stat })
      return
    }

    this.recoverRecentEvents({ stat })
    this.offset = stat.size
    this.partial = ''
    this.recovery = {
      ...this.recovery,
      recovered: true,
      mode: 'tail-scan',
      unreadBytes: 0,
      previousOffset: Number.isInteger(cursor.offset) ? cursor.offset : 0,
      currentOffset: this.offset,
      reason: previous ? 'persisted cursor was stale or for another log' : 'no persisted cursor',
    }
    this.persist({ stat })
  }

  recoverRecentEvents({ stat, endOffset = stat.size }) {
    const beforeCount = this.events.length
    const boundedEndOffset = Math.max(0, Math.min(endOffset, stat.size))
    if (boundedEndOffset <= 0) return
    const length = Math.min(boundedEndOffset, DEFAULT_RECOVERY_TAIL_BYTES)
    const offset = boundedEndOffset - length
    const fd = fs.openSync(this.eventLogPath, 'r')
    try {
      const buffer = Buffer.alloc(length)
      fs.readSync(fd, buffer, 0, length, offset)
      const lines = buffer.toString('utf8').split(/\r?\n/)
      if (offset > 0) lines.shift()
      if (lines[lines.length - 1] === '') lines.pop()
      for (const line of lines) {
        if (!line.trim()) continue
        const classified = classifyEventLine(line)
        if (classified.invalidReason) {
          this.invalidLineCount += 1
          this.lastInvalidLine = {
            at: new Date().toISOString(),
            reason: classified.invalidReason,
            message: classified.message,
          }
          continue
        }
        if (classified.tamperReason) {
          this.tamperLineCount += 1
          this.lastTamperLine = {
            at: new Date().toISOString(),
            reason: classified.tamperReason,
            message: classified.message,
          }
          continue
        }
        this.push(classified.event)
      }
      this.lastReadAt = new Date().toISOString()
      this.recovery.recoveredEventCount = this.events.length - beforeCount
    } finally {
      fs.closeSync(fd)
    }
  }

  recordTruncation(event) {
    this.retention = {
      ...this.retention,
      truncated: true,
      lastTruncatedAt: event.at,
      lastTruncation: {
        at: event.at,
        beforeBytes: event.beforeBytes,
        afterBytes: event.afterBytes,
        keepBytes: event.keepBytes,
        maxKeepBytes: event.maxKeepBytes,
        eventLogPath: event.path,
      },
    }
    this.persist()
  }

  metadata({ stat = null } = {}) {
    const currentStat = stat || (() => {
      try {
        return fs.statSync(this.eventLogPath)
      } catch {
        return null
      }
    })()
    return {
      schemaVersion: EVENT_STORAGE_SCHEMA_VERSION,
      eventSchemaVersion: EVENT_LOG_SCHEMA_VERSION,
      service: 'guardd',
      updatedAt: new Date().toISOString(),
      migrations: this.storageMigrations,
      cursor: {
        eventLogPath: this.eventLogPath,
        offset: this.offset,
        partial: this.partial,
        identity: currentStat ? statIdentity(currentStat) : null,
      },
      tail: {
        retainedEventCount: this.events.length,
        maxEvents: this.maxEvents,
        invalidLineCount: this.invalidLineCount,
        tamperLineCount: this.tamperLineCount,
        lastInvalidLine: this.lastInvalidLine,
        lastTamperLine: this.lastTamperLine,
        lastReadAt: this.lastReadAt,
        readError: this.readError,
      },
      recovery: this.recovery,
      retention: this.retention,
      index: this.index.payload(),
    }
  }

  persist({ stat = null } = {}) {
    try {
      fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 })
      writeJsonFile(this.metadataPath, this.metadata({ stat }))
      this.lastPersistedAt = new Date().toISOString()
    } catch (error) {
      this.readError = this.readError || `metadata persist failed: ${error.message}`
    }
  }
}

const appendJsonLine = (target, value) => {
  try {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.appendFileSync(target, `${JSON.stringify(value)}\n`)
  } catch {}
}

const fileExists = (target) => {
  try {
    return fs.statSync(target).isFile()
  } catch {
    return false
  }
}

const fileSize = (target) => {
  try {
    return fs.statSync(target).size
  } catch {
    return 0
  }
}

const fileMode = (target) => {
  try {
    return fs.statSync(target).mode & 0o777
  } catch {
    return null
  }
}

const octalMode = (mode) => (mode === null ? null : `0${mode.toString(8).padStart(3, '0')}`)

const modeAllowsGroupOrOther = (mode, mask = 0o077) => mode !== null && (mode & mask) !== 0

const sha256Hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex')

const tokenFingerprint = (token) => (token ? `sha256:${sha256Hex(token).slice(0, 16)}` : '')

const tokenMatches = (provided, expected) => {
  if (!expected) return true
  if (!provided) return false
  const providedBuffer = Buffer.from(String(provided))
  const expectedBuffer = Buffer.from(String(expected))
  return providedBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(providedBuffer, expectedBuffer)
}

const keychainEnabled = (env = process.env) =>
  env.GUARDD_TOKEN_KEYCHAIN === '1' || env.GUARD_TOKEN_KEYCHAIN === '1'

const keychainTokenDescriptor = (env = process.env) => ({
  ready: process.platform === 'darwin',
  enabled: keychainEnabled(env),
  provider: 'macos-keychain',
  service: env.GUARDD_TOKEN_KEYCHAIN_SERVICE || DEFAULT_KEYCHAIN_TOKEN_SERVICE,
  account: env.GUARDD_TOKEN_KEYCHAIN_ACCOUNT || DEFAULT_KEYCHAIN_TOKEN_ACCOUNT,
  label: 'Guard daemon API token',
  accessGroup: null,
  invokedByGuardd: false,
  readAtStartup: false,
  lastPersistedAt: null,
  lastError: '',
})

const runSecurity = (args) => execFileSync('/usr/bin/security', args, {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
})

const readTokenFromKeychain = (descriptor) => {
  if (process.platform !== 'darwin') return { token: '', error: 'keychain is only available on macOS' }
  try {
    const token = runSecurity([
      'find-generic-password',
      '-w',
      '-s',
      descriptor.service,
      '-a',
      descriptor.account,
    ]).trim()
    return { token, error: '' }
  } catch (error) {
    return { token: '', error: error.stderr?.toString().trim() || error.message }
  }
}

const writeTokenToKeychain = ({ token, descriptor }) => {
  if (process.platform !== 'darwin') {
    const error = new Error('keychain is only available on macOS')
    error.code = 'keychain_unavailable'
    throw error
  }
  runSecurity([
    'add-generic-password',
    '-U',
    '-s',
    descriptor.service,
    '-a',
    descriptor.account,
    '-l',
    descriptor.label,
    '-w',
    token,
  ])
}

const createAuthState = (apiToken, env = process.env) => {
  const descriptor = keychainTokenDescriptor(env)
  let currentToken = String(apiToken || '')
  let storage = 'runtime-memory'
  if (!currentToken && descriptor.enabled) {
    const keychain = readTokenFromKeychain(descriptor)
    descriptor.invokedByGuardd = true
    descriptor.readAtStartup = Boolean(keychain.token)
    descriptor.lastError = keychain.error
    if (keychain.token) {
      currentToken = keychain.token
      storage = 'macos-keychain'
    }
  }
  return {
    currentToken,
    storage,
    keychainDescriptor: descriptor,
    configuredAt: new Date().toISOString(),
    rotatedAt: null,
    rotationCount: 0,
  }
}

const authTokenMetadata = (authState) => ({
  configured: Boolean(authState.currentToken),
  required: Boolean(authState.currentToken),
  fingerprint: tokenFingerprint(authState.currentToken),
  length: authState.currentToken ? authState.currentToken.length : 0,
  storage: authState.storage || 'runtime-memory',
  secretExposed: false,
  configuredAt: authState.configuredAt,
  rotatedAt: authState.rotatedAt,
  rotationCount: authState.rotationCount,
  rotation: {
    supported: true,
    endpoint: '/auth/token/rotate',
    scope: 'current-daemon-process',
    persistsAcrossRestart: authState.storage === 'macos-keychain',
    requiresExistingToken: true,
    requiresLocalClient: true,
  },
  keychainDescriptor: authState.keychainDescriptor || keychainTokenDescriptor(),
})

const rotateRuntimeToken = ({ authState, request, body = {} }) => {
  if (!authState.currentToken) {
    const error = new Error('runtime token rotation requires a configured token')
    error.code = 'token_not_configured'
    throw error
  }
  if (!isLoopbackHost(request.socket?.remoteAddress)) {
    const error = new Error('runtime token rotation is limited to loopback clients')
    error.code = 'local_client_required'
    throw error
  }
  const newToken = body.token || body.newToken || crypto.randomBytes(32).toString('base64url')
  if (typeof newToken !== 'string' || newToken.length < 20) {
    const error = new Error('new runtime token must be at least 20 characters')
    error.code = 'weak_token'
    throw error
  }
  if (tokenMatches(newToken, authState.currentToken)) {
    const error = new Error('new runtime token must differ from the current token')
    error.code = 'token_unchanged'
    throw error
  }
  const previousFingerprint = tokenFingerprint(authState.currentToken)
  authState.currentToken = newToken
  if (body.persist === true || body.storage === 'macos-keychain') {
    writeTokenToKeychain({ token: newToken, descriptor: authState.keychainDescriptor })
    authState.storage = 'macos-keychain'
    authState.keychainDescriptor.enabled = true
    authState.keychainDescriptor.invokedByGuardd = true
    authState.keychainDescriptor.lastPersistedAt = new Date().toISOString()
    authState.keychainDescriptor.lastError = ''
  } else {
    authState.storage = 'runtime-memory'
  }
  authState.rotatedAt = new Date().toISOString()
  authState.rotationCount += 1
  return {
    action: 'rotate-runtime-token',
    changed: true,
    previousFingerprint,
    token: body.returnToken === false ? undefined : newToken,
    auth: authTokenMetadata(authState),
  }
}

const persistRuntimeToken = ({ authState }) => {
  if (!authState.currentToken) {
    const error = new Error('runtime token is not configured')
    error.code = 'token_not_configured'
    throw error
  }
  writeTokenToKeychain({ token: authState.currentToken, descriptor: authState.keychainDescriptor })
  authState.storage = 'macos-keychain'
  authState.keychainDescriptor.enabled = true
  authState.keychainDescriptor.invokedByGuardd = true
  authState.keychainDescriptor.lastPersistedAt = new Date().toISOString()
  authState.keychainDescriptor.lastError = ''
  return {
    action: 'persist-runtime-token',
    changed: true,
    auth: authTokenMetadata(authState),
  }
}

const isSafeName = (name) => /^[A-Za-z0-9._-]+$/.test(name)
const listJsonFiles = (dir) => {
  try {
    return fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
      .map((entry) => path.join(dir, entry.name))
      .sort((left, right) => left.localeCompare(right))
  } catch (error) {
    if (error.code === 'ENOENT') return []
    throw error
  }
}

const profileSummary = ({ filePath, source }) => {
  const config = readJsonFile(filePath)
  const name = path.basename(filePath, '.json')
  const network = config.network || {}
  return {
    name,
    source,
    path: filePath,
    description: config.metadata?.description || '',
    risk: config.metadata?.risk || 'unknown',
    status: config.metadata?.status || 'unknown',
    imports: Array.isArray(config.imports) ? config.imports : [],
    allowedDomainsCount: Array.isArray(network.allowedDomains)
      ? network.allowedDomains.length
      : 0,
    deniedDomainsCount: Array.isArray(network.deniedDomains)
      ? network.deniedDomains.length
      : 0,
    ...profileVersionInfo(config),
  }
}

const templateSummary = (templatePath) => {
  const config = readJsonFile(templatePath)
  return {
    name: path.basename(path.dirname(templatePath)),
    source: 'template',
    path: templatePath,
    description: config.metadata?.description || '',
    risk: config.metadata?.risk || 'unknown',
    status: config.metadata?.status || 'template',
    imports: Array.isArray(config.imports) ? config.imports : [],
    ...profileVersionInfo(config),
  }
}

const normalizeMatchVersion = (value) => {
  if (value === undefined || value === null || value === '') return ''
  const text = String(value).trim()
  if (text === '*') return text
  return text.replace(/^W\//, '').replace(/^"|"$/g, '')
}

const readIfMatch = (request, body = {}) => {
  const header = request.headers['if-match']
  const value = Array.isArray(header) ? header[0] : header
  return normalizeMatchVersion(value || body.ifMatch || body.version || body.profileVersion)
}

const assertVersionMatch = ({ expected, actual, profile }) => {
  if (!expected || expected === '*') return
  if (normalizeMatchVersion(expected) !== normalizeMatchVersion(actual)) {
    const error = new Error(`profile version mismatch for ${profile}: expected ${expected}, current ${actual}`)
    error.code = 'version_mismatch'
    error.statusCode = 412
    error.expectedVersion = expected
    error.currentVersion = actual
    throw error
  }
}

const summarizeConfig = (config = {}) => {
  const network = config.network || {}
  const filesystem = config.filesystem || {}
  const ruleMetadata = config.ruleMetadata && typeof config.ruleMetadata === 'object' && !Array.isArray(config.ruleMetadata)
    ? config.ruleMetadata
    : {}
  return {
    imports: Array.isArray(config.imports) ? config.imports : [],
    network: {
      backend: network.backend || '',
      allowedDomainsCount: Array.isArray(network.allowedDomains) ? network.allowedDomains.length : 0,
      deniedDomainsCount: Array.isArray(network.deniedDomains) ? network.deniedDomains.length : 0,
      httpRulesCount: Array.isArray(network.httpRules) ? network.httpRules.length : 0,
      allowedRawTcpCount: Array.isArray(network.allowedRawTcp) ? network.allowedRawTcp.length : 0,
      secretInjectionCount: Array.isArray(network.secretInjection || network.secrets) ? (network.secretInjection || network.secrets).length : 0,
      tlsInspection: network.tlsInspection || null,
    },
    filesystem: {
      allowReadCount: Array.isArray(filesystem.allowRead) ? filesystem.allowRead.length : 0,
      denyReadCount: Array.isArray(filesystem.denyRead) ? filesystem.denyRead.length : 0,
      allowWriteCount: Array.isArray(filesystem.allowWrite) ? filesystem.allowWrite.length : 0,
      denyWriteCount: Array.isArray(filesystem.denyWrite) ? filesystem.denyWrite.length : 0,
    },
    disabledRulesCount: Object.values(ruleMetadata).filter((entry) => entry?.disabled === true).length,
  }
}

class PolicyStore {
  constructor({ policyRoot, repoRoot }) {
    this.policyRoot = policyRoot
    this.repoRoot = repoRoot
    this.projectProfilesDir = path.join(policyRoot, '.guard')
    this.builtinProfilesDir = path.join(repoRoot, 'profiles')
    this.templatesDir = path.join(repoRoot, 'templates')
  }

  listProfiles() {
    const profiles = [
      ...listJsonFiles(this.projectProfilesDir).map((filePath) =>
        profileSummary({ filePath, source: 'project' }),
      ),
      ...listJsonFiles(this.builtinProfilesDir).map((filePath) =>
        profileSummary({ filePath, source: 'builtin' }),
      ),
    ]
    return profiles.sort((left, right) =>
      `${left.name}:${left.source}`.localeCompare(`${right.name}:${right.source}`),
    )
  }

  resolveProfilePath(name) {
    if (!isSafeName(name)) return null
    const projectPath = path.join(this.projectProfilesDir, `${name}.json`)
    if (fs.existsSync(projectPath)) return { source: 'project', path: projectPath }
    const builtinPath = path.join(this.builtinProfilesDir, `${name}.json`)
    if (fs.existsSync(builtinPath)) return { source: 'builtin', path: builtinPath }
    return null
  }

  resolveProjectProfilePath(name) {
    if (!isSafeName(name)) return null
    const projectPath = path.join(this.projectProfilesDir, `${name}.json`)
    return fs.existsSync(projectPath) ? projectPath : null
  }

  writableProfilePath(name) {
    if (!isSafeName(name)) return null
    const projectPath = path.join(this.projectProfilesDir, `${name}.json`)
    if (fs.existsSync(projectPath)) return projectPath
    const resolved = this.resolveProfilePath(name)
    if (!resolved) return null
    const config = loadProfileConfig({ repoRoot: this.repoRoot, configPath: resolved.path })
    writeJsonFile(projectPath, {
      ...config,
      metadata: {
        ...(config.metadata && typeof config.metadata === 'object' && !Array.isArray(config.metadata)
          ? config.metadata
          : {}),
        source: 'guardd-global-config',
      },
    })
    return projectPath
  }

  getProfile(name) {
    const resolved = this.resolveProfilePath(name)
    if (!resolved) return null
    const config = readJsonFile(resolved.path)
    return {
      name,
      source: resolved.source,
      path: resolved.path,
      ...profileVersionInfo(config),
      config,
    }
  }

  getEffectivePolicy(name) {
    const resolved = this.resolveProfilePath(name)
    if (!resolved) return null
    const rawConfig = readJsonFile(resolved.path)
    const config = loadProfileConfig({ repoRoot: this.repoRoot, configPath: resolved.path })
    const effectiveVersion = profileVersionInfo(config)
    return {
      name,
      source: resolved.source,
      path: resolved.path,
      ...profileVersionInfo(rawConfig),
      effectiveVersion: effectiveVersion.version,
      effectiveHash: effectiveVersion.hash,
      effectiveShortHash: effectiveVersion.shortHash,
      config,
    }
  }

  listTemplates() {
    let entries
    try {
      entries = fs.readdirSync(this.templatesDir, { withFileTypes: true })
    } catch (error) {
      if (error.code === 'ENOENT') return []
      throw error
    }
    return entries
      .filter((entry) => entry.isDirectory() && entry.name !== 'imports')
      .map((entry) => path.join(this.templatesDir, entry.name, 'guard.json'))
      .filter((templatePath) => fs.existsSync(templatePath))
      .map((templatePath) => templateSummary(templatePath))
      .sort((left, right) => left.name.localeCompare(right.name))
  }

  getTemplate(name) {
    if (!isSafeName(name)) return null
    const templatePath = path.join(this.templatesDir, name, 'guard.json')
    if (!fs.existsSync(templatePath)) return null
    const config = readJsonFile(templatePath)
    return {
      name,
      source: 'template',
      path: templatePath,
      ...profileVersionInfo(config),
      config,
    }
  }

  mutateArrayRule({ profile, field, value, action, ifMatch, disabled = false }) {
    if (!MUTABLE_PROFILE_ARRAY_FIELDS.has(field)) throw new Error(`unsupported profile field: ${field}`)
    const profilePath = this.writableProfilePath(profile)
    if (!profilePath) throw new Error(`project profile not found: ${profile}`)
    const cfg = readJsonFile(profilePath)
    const beforeVersion = profileVersion(cfg)
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion, profile })
    const result = mutateArrayRuleConfig({
      cfg,
      field,
      value,
      action,
      disabled,
      source: 'guardd',
    })
    if (result.changed) writeJsonFile(profilePath, cfg)
    return {
      ...result,
      profile,
      path: profilePath,
      beforeVersion,
      ...profileVersionInfo(cfg),
    }
  }

  mutateHttpRule({ profile, rule, action, ifMatch, disabled = false }) {
    const profilePath = this.writableProfilePath(profile)
    if (!profilePath) throw new Error(`project profile not found: ${profile}`)
    const cfg = readJsonFile(profilePath)
    const beforeVersion = profileVersion(cfg)
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion, profile })
    const result = mutateHttpRuleConfig({
      cfg,
      rule,
      action,
      disabled,
      source: 'guardd',
    })
    if (result.changed) writeJsonFile(profilePath, cfg)
    return {
      ...result,
      profile,
      path: profilePath,
      beforeVersion,
      ...profileVersionInfo(cfg),
    }
  }

  mutateTls({ profile, enabled, ifMatch }) {
    const profilePath = this.writableProfilePath(profile)
    if (!profilePath) throw new Error(`project profile not found: ${profile}`)
    const cfg = readJsonFile(profilePath)
    const beforeVersion = profileVersion(cfg)
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion, profile })
    const result = mutateTlsConfig({ cfg, enabled })
    if (result.changed) writeJsonFile(profilePath, cfg)
    return {
      ...result,
      tlsChanged: result.changed,
      profile,
      path: profilePath,
      beforeVersion,
      ...profileVersionInfo(cfg),
    }
  }

  previewTemplate({ template, profile = 'guard' }) {
    if (!isSafeName(profile)) throw new Error(`invalid profile name: ${profile}`)
    const source = this.getTemplate(template)
    if (!source) throw new Error(`template not found: ${template}`)
    const targetPath = path.join(this.projectProfilesDir, `${profile}.json`)
    const existingConfig = fs.existsSync(targetPath) ? readJsonFile(targetPath) : null
    const sourceEffectiveConfig = loadProfileConfig({ repoRoot: this.repoRoot, configPath: source.path })
    const effectiveConfig = existingConfig
      ? mergeProfileConfig(existingConfig, sourceEffectiveConfig)
      : structuredClone(sourceEffectiveConfig)
    return {
      action: 'preview-template',
      changed: false,
      template,
      profile,
      sourcePath: source.path,
      path: targetPath,
      targetPath,
      existing: Boolean(existingConfig),
      existingVersion: existingConfig ? profileVersion(existingConfig) : null,
      templateVersion: source.version,
      effective: {
        ...profileVersionInfo(effectiveConfig),
        summary: summarizeConfig(effectiveConfig),
      },
    }
  }

  applyTemplate({ template, profile = 'guard', force = false, ifMatch }) {
    if (!isSafeName(profile)) throw new Error(`invalid profile name: ${profile}`)
    const source = this.getTemplate(template)
    if (!source) throw new Error(`template not found: ${template}`)
    const targetPath = path.join(this.projectProfilesDir, `${profile}.json`)
    const existingConfig = fs.existsSync(targetPath) ? readJsonFile(targetPath) : null
    const beforeVersion = existingConfig ? profileVersion(existingConfig) : null
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion || '', profile })
    if (fs.existsSync(targetPath) && !force) {
      throw new Error(`project profile exists: ${profile}`)
    }
    writeJsonFile(targetPath, source.config)
    return {
      action: 'apply-template',
      changed: true,
      template,
      profile,
      sourcePath: source.path,
      path: targetPath,
      force,
      beforeVersion,
      ...profileVersionInfo(source.config),
    }
  }
}

const writeJson = (response, statusCode, payload) => {
  const body = `${JSON.stringify(payload, null, 2)}\n`
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
  })
  response.end(body)
}

const isLoopbackHost = (host) =>
  host === '127.0.0.1' || host === '::1' || host === '::ffff:127.0.0.1' || host === 'localhost'

const extractToken = (request) => {
  const authorization = request.headers.authorization || ''
  if (authorization.startsWith('Bearer ')) return authorization.slice('Bearer '.length)
  const headerToken = request.headers['x-guard-token']
  return Array.isArray(headerToken) ? headerToken[0] : headerToken || ''
}

const isAuthorized = (request, authState) => !authState.currentToken || tokenMatches(extractToken(request), authState.currentToken)

const daemonStatePayload = ({ tail, policyStore, startedAt, authState, stateDir, eventLogPath }) => ({
  ok: true,
  service: 'guardd',
  apiVersion: GUARDD_API_VERSION,
  version: `guardd-api-${GUARDD_API_VERSION}`,
  startedAt,
  state: {
    pid: process.pid,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
  },
  paths: {
    stateDir,
    eventLogPath,
    policyRoot: policyStore.policyRoot,
    projectProfilesDir: policyStore.projectProfilesDir,
    builtinProfilesDir: policyStore.builtinProfilesDir,
    templatesDir: policyStore.templatesDir,
    repoRoot: policyStore.repoRoot,
  },
  auth: {
    required: Boolean(authState.currentToken),
    mutationTokenRequired: true,
    token: authTokenMetadata(authState),
  },
  tail: {
    retainedEventCount: tail.events.length,
    maxEvents: tail.maxEvents,
    pollMs: tail.pollMs,
    invalidLineCount: tail.invalidLineCount,
    tamperLineCount: tail.tamperLineCount,
    lastInvalidLine: tail.lastInvalidLine,
    lastTamperLine: tail.lastTamperLine,
    lastReadAt: tail.lastReadAt,
    lastPersistedAt: tail.lastPersistedAt,
    readError: tail.readError,
    eventLogSize: fileSize(tail.eventLogPath),
    offset: tail.offset,
    metadataPath: tail.metadataPath,
    recovery: tail.recovery,
    retention: tail.retention,
    index: tail.index.payload(),
  },
})

const tlsCaMetadata = ({ stateDir }) => {
  const caDir = path.join(stateDir, 'tls-ca')
  const certificatePath = path.join(caDir, 'guard-local-ca.pem')
  const privateKeyPath = path.join(caDir, 'guard-local-ca-key.pem')
  const bundlePath = path.join(caDir, 'guard-local-ca-bundle.pem')
  const metadataPath = path.join(caDir, 'guard-local-ca.json')
  const metadata = fileExists(metadataPath) ? readJsonFile(metadataPath) : {}
  const privateKeyMode = fileMode(privateKeyPath)
  const caDirMode = fileMode(caDir)
  return {
    scaffold: false,
    installedGlobally: false,
    globalTrustManaged: false,
    trustStoreAction: 'not-managed-by-guardd',
    userApprovalRequired: true,
    mode: 'ephemeral-run-ca',
    scope: 'guarded-process-env',
    lifecycle: metadata.lifecycle || 'missing',
    serial: metadata.serial || '',
    subject: metadata.subject || 'CN=Guard Local Development CA',
    createdAt: metadata.createdAt || null,
    rotatedAt: metadata.rotatedAt || null,
    revokedAt: metadata.revokedAt || null,
    paths: {
      caDir,
      certificatePath,
      privateKeyPath,
      bundlePath,
      metadataPath,
    },
    generated: {
      caDir: fs.existsSync(caDir),
      certificate: fileExists(certificatePath),
      privateKey: fileExists(privateKeyPath),
      bundle: fileExists(bundlePath),
      metadata: fileExists(metadataPath),
    },
    privateKeyProtection: {
      storage: 'filesystem',
      secretExposed: false,
      expectedMode: '0600',
      actualMode: octalMode(privateKeyMode),
      modeOk: !fileExists(privateKeyPath) || privateKeyMode === 0o600,
      directoryMode: octalMode(caDirMode),
      directoryModeOk: !fs.existsSync(caDir) || !modeAllowsGroupOrOther(caDirMode, 0o077),
      keychainReady: true,
      keychainDescriptor: {
        provider: 'macos-keychain',
        service: 'com.guard.guardd.tls-ca',
        account: 'guard-local-ca',
        label: 'Guard Local Development CA private key',
        accessGroup: null,
        invokedByGuardd: false,
      },
    },
  }
}

const sanitizeTlsHost = (host) => {
  const normalized = String(host || '').trim().toLowerCase()
  if (!normalized || normalized.length > 253) throw new Error('host is required')
  if (!/^[a-z0-9.*:-]+$/.test(normalized)) throw new Error(`invalid host: ${host}`)
  if (normalized.includes('/') || normalized.includes('\\') || normalized.includes('..')) {
    throw new Error(`invalid host: ${host}`)
  }
  return normalized
}

const tlsHostFileStem = (host) =>
  sanitizeTlsHost(host).replace(/^\*\./, 'wildcard.').replace(/[^a-z0-9.-]+/g, '_')

const tlsHostCertificateMetadata = ({ stateDir, host }) => {
  const normalizedHost = sanitizeTlsHost(host)
  const ca = tlsCaMetadata({ stateDir })
  const issuedDir = path.join(ca.paths.caDir, 'issued')
  const stem = tlsHostFileStem(normalizedHost)
  const certificatePath = path.join(issuedDir, `${stem}.pem`)
  const privateKeyPath = path.join(issuedDir, `${stem}-key.pem`)
  const metadataPath = path.join(issuedDir, `${stem}.json`)
  const metadata = fileExists(metadataPath) ? readJsonFile(metadataPath) : {}
  return {
    scaffold: false,
    installedGlobally: false,
    globalTrustManaged: false,
    trustStoreAction: 'not-managed-by-guardd',
    userApprovalRequired: true,
    mode: 'ephemeral-run-ca',
    scope: 'guarded-process-env',
    lifecycle: metadata.lifecycle || 'missing',
    host: normalizedHost,
    subject: metadata.subject || `CN=${normalizedHost}`,
    createdAt: metadata.createdAt || null,
    expiresAt: metadata.expiresAt || null,
    caLifecycle: ca.lifecycle,
    paths: {
      issuedDir,
      certificatePath,
      privateKeyPath,
      metadataPath,
      caCertificatePath: ca.paths.certificatePath,
    },
    generated: {
      issuedDir: fs.existsSync(issuedDir),
      certificate: fileExists(certificatePath),
      privateKey: fileExists(privateKeyPath),
      metadata: fileExists(metadataPath),
      caCertificate: ca.generated.certificate,
    },
  }
}

const listIssuedTlsCertificates = ({ stateDir }) => {
  const ca = tlsCaMetadata({ stateDir })
  const issuedDir = path.join(ca.paths.caDir, 'issued')
  let entries = []
  try {
    entries = fs.readdirSync(issuedDir, { withFileTypes: true })
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  const now = Date.now()
  const certificates = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => {
      const metadataPath = path.join(issuedDir, entry.name)
      const metadata = safeReadJsonFile(metadataPath, {})
      const host = metadata.host || entry.name.replace(/\.json$/, '')
      const certificate = tlsHostCertificateMetadata({ stateDir, host })
      const expiresAtMs = certificate.expiresAt ? Date.parse(certificate.expiresAt) : NaN
      return {
        host: certificate.host,
        lifecycle: certificate.lifecycle,
        createdAt: certificate.createdAt,
        expiresAt: certificate.expiresAt,
        expired: Number.isFinite(expiresAtMs) ? expiresAtMs <= now : false,
        paths: certificate.paths,
        generated: certificate.generated,
      }
    })
    .sort((left, right) => left.host.localeCompare(right.host))
  return {
    issuedDir,
    count: certificates.length,
    activeCount: certificates.filter((entry) => entry.lifecycle === 'active' && !entry.expired).length,
    expiredCount: certificates.filter((entry) => entry.expired).length,
    certificates,
  }
}

const tlsTrustStatus = ({ stateDir }) => {
  const ca = tlsCaMetadata({ stateDir })
  const issued = listIssuedTlsCertificates({ stateDir })
  const findings = []
  if (ca.lifecycle !== 'active') {
    findings.push({
      severity: 'medium',
      id: 'tls-ca-not-active',
      message: `Local TLS CA lifecycle is ${ca.lifecycle}. Generate or rotate it before decrypted TLS inspection.`,
    })
  }
  if (ca.generated.privateKey && fileMode(ca.paths.privateKeyPath) !== 0o600) {
    findings.push({
      severity: 'high',
      id: 'tls-ca-key-permissions',
      message: `Local CA key mode is ${octalMode(fileMode(ca.paths.privateKeyPath))}; expected 0600.`,
      path: ca.paths.privateKeyPath,
    })
  }
  if (issued.expiredCount > 0) {
    findings.push({
      severity: 'low',
      id: 'tls-leaf-expired',
      message: `${issued.expiredCount} cached host certificate(s) are expired and should be regenerated.`,
    })
  }
  return {
    ok: findings.every((finding) => finding.severity !== 'high'),
    globalTrustManaged: false,
    trustStoreAction: 'not-managed-by-guardd',
    userApprovalRequired: true,
    onboarding: {
      caScope: 'guarded-process-env',
      installGlobalTrust: false,
      diagnostic: 'Guard only exposes local CA artifacts and per-process trust environment variables in this feature build.',
      environmentVariables: ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'GIT_SSL_CAINFO'],
    },
    ca,
    issued,
    findings,
  }
}

const extensionSyncPaths = ({ stateDir }) => {
  const dir = path.join(stateDir, 'network-extension')
  return {
    dir,
    manifestPath: path.join(dir, 'manifest.json'),
    policyPath: path.join(dir, 'policy.json'),
    eventLogPath: path.join(dir, 'events.jsonl'),
    heartbeatPath: path.join(dir, 'heartbeat.json'),
  }
}

const extensionSyncState = ({ stateDir }) => {
  const paths = extensionSyncPaths({ stateDir })
  const manifest = fileExists(paths.manifestPath) ? readJsonFile(paths.manifestPath) : null
  const heartbeat = fileExists(paths.heartbeatPath) ? readJsonFile(paths.heartbeatPath) : null
  let policyDigest = ''
  if (fileExists(paths.policyPath)) {
    policyDigest = `sha256:${crypto.createHash('sha256').update(fs.readFileSync(paths.policyPath)).digest('hex')}`
  }
  return {
    syncVersion: EXTENSION_SYNC_VERSION,
    configured: Boolean(manifest),
    paths,
    manifest,
    heartbeat,
    policyDigest,
    validPolicyDigest: Boolean(manifest?.policyDigest && policyDigest && manifest.policyDigest === policyDigest),
    invalidated: Boolean(manifest?.invalidatedAt),
    generated: {
      dir: fs.existsSync(paths.dir),
      manifest: fileExists(paths.manifestPath),
      policy: fileExists(paths.policyPath),
      events: fileExists(paths.eventLogPath),
      heartbeat: fileExists(paths.heartbeatPath),
    },
  }
}

const writeExtensionSync = ({ stateDir, policyStore, profile = 'guard', eventLogPath, mode = 'permissive-fallback' }) => {
  const policy = policyStore.getEffectivePolicy(profile)
  if (!policy) {
    const error = new Error(`profile not found: ${profile}`)
    error.code = 'profile_not_found'
    throw error
  }
  const paths = extensionSyncPaths({ stateDir })
  fs.mkdirSync(paths.dir, { recursive: true, mode: 0o700 })
  const now = new Date().toISOString()
  const previous = fileExists(paths.manifestPath) ? readJsonFile(paths.manifestPath) : {}
  const sequence = Number.isInteger(previous.sequence) ? previous.sequence + 1 : 1
  const policySnapshot = buildPolicySnapshot({
    config: policy.config,
    profile,
    projectDir: policyStore.policyRoot,
    generatedAt: now,
    sequence,
    source: policy.source,
    rawVersion: policy.version,
    effectiveVersion: policy.effectiveVersion,
  })
  writeJsonFile(paths.policyPath, policySnapshot)
  const policyDigest = `sha256:${crypto.createHash('sha256').update(fs.readFileSync(paths.policyPath)).digest('hex')}`
  const manifest = {
    syncVersion: EXTENSION_SYNC_VERSION,
    sequence,
    generatedAt: now,
    profile,
    mode,
    policyDigest,
    invalidatedAt: null,
    invalidateReason: '',
    maxPolicyAgeSeconds: 30,
    maxEventBacklogBytes: 1024 * 1024,
    fallback: {
      unavailable: mode,
      stalePolicy: mode,
      eventBackpressure: 'allow-with-backpressure-event',
    },
    paths: {
      policyPath: paths.policyPath,
      eventLogPath: paths.eventLogPath,
      heartbeatPath: paths.heartbeatPath,
      daemonEventLogPath: eventLogPath,
    },
    version: policy.effectiveVersion,
  }
  writeJsonFile(paths.manifestPath, manifest)
  writeJsonFile(paths.heartbeatPath, {
    syncVersion: EXTENSION_SYNC_VERSION,
    sequence,
    at: now,
    service: 'guardd',
    pid: process.pid,
  })
  return {
    action: 'extension-sync',
    changed: true,
    profile,
    path: paths.manifestPath,
    sequence,
    version: policy.effectiveVersion,
    ...extensionSyncState({ stateDir }),
  }
}

const invalidateExtensionSync = ({ stateDir, reason = 'manual-invalidation' }) => {
  const paths = extensionSyncPaths({ stateDir })
  fs.mkdirSync(paths.dir, { recursive: true, mode: 0o700 })
  const now = new Date().toISOString()
  const previous = fileExists(paths.manifestPath) ? readJsonFile(paths.manifestPath) : {}
  const sequence = Number.isInteger(previous.sequence) ? previous.sequence + 1 : 1
  const manifest = {
    ...previous,
    syncVersion: EXTENSION_SYNC_VERSION,
    sequence,
    generatedAt: previous.generatedAt || now,
    invalidatedAt: now,
    invalidateReason: String(reason || 'manual-invalidation'),
    fallback: {
      unavailable: previous.fallback?.unavailable || 'strict-deny',
      stalePolicy: 'strict-deny',
      eventBackpressure: previous.fallback?.eventBackpressure || 'allow-with-backpressure-event',
    },
    paths: previous.paths || {
      policyPath: paths.policyPath,
      eventLogPath: paths.eventLogPath,
      heartbeatPath: paths.heartbeatPath,
    },
  }
  writeJsonFile(paths.manifestPath, manifest)
  return {
    action: 'extension-sync-invalidate',
    changed: true,
    sequence,
    reason: manifest.invalidateReason,
    ...extensionSyncState({ stateDir }),
  }
}

const opensslPath = () => process.env.GUARDD_OPENSSL || '/usr/bin/openssl'

const tlsSubjectAltName = (host) =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')
    ? `IP:${host}`
    : `DNS:${host}`

const generateTlsCa = ({ stateDir, rotate = false, days = 30, commonName = 'Guard Local Development CA' }) => {
  const current = tlsCaMetadata({ stateDir })
  const caDir = current.paths.caDir
  fs.mkdirSync(caDir, { recursive: true, mode: 0o700 })
  const existing = current.generated.certificate || current.generated.privateKey || current.generated.metadata
  if (existing && !rotate) {
    return { action: 'generate-ca', changed: false, ...tlsCaMetadata({ stateDir }) }
  }

  const now = new Date().toISOString()
  if (existing && rotate) {
    const archiveDir = path.join(caDir, `archive-${now.replace(/[:.]/g, '-')}`)
    fs.mkdirSync(archiveDir, { recursive: true, mode: 0o700 })
    for (const source of [current.paths.certificatePath, current.paths.privateKeyPath, current.paths.bundlePath, current.paths.metadataPath]) {
      if (fileExists(source)) fs.renameSync(source, path.join(archiveDir, path.basename(source)))
    }
  }

  const serial = `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 10)}`
  execFileSync(opensslPath(), [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-sha256',
    '-nodes',
    '-days',
    String(days),
    '-subj',
    `/CN=${commonName.replace(/[\\/]/g, ' ')}/O=Guard Local Development`,
    '-keyout',
    current.paths.privateKeyPath,
    '-out',
    current.paths.certificatePath,
  ], { stdio: 'ignore' })
  fs.chmodSync(current.paths.privateKeyPath, 0o600)
  fs.copyFileSync(current.paths.certificatePath, current.paths.bundlePath)
  writeJsonFile(current.paths.metadataPath, {
    lifecycle: 'active',
    serial,
    subject: `CN=${commonName}`,
    createdAt: now,
    rotatedAt: rotate ? now : null,
    days,
    installedGlobally: false,
    globalTrustManaged: false,
  })
  return { action: rotate ? 'rotate-ca' : 'generate-ca', changed: true, ...tlsCaMetadata({ stateDir }) }
}

const issueTlsHostCertificate = ({ stateDir, host, days = 7, force = false }) => {
  const normalizedHost = sanitizeTlsHost(host)
  const current = tlsHostCertificateMetadata({ stateDir, host: normalizedHost })
  const ca = tlsCaMetadata({ stateDir })
  if (ca.lifecycle !== 'active' || !ca.generated.certificate || !ca.generated.privateKey) {
    const error = new Error('active local TLS CA is required before issuing host certificates')
    error.code = 'ca_missing'
    throw error
  }
  if (current.generated.certificate && current.generated.privateKey && current.generated.metadata && !force) {
    return { action: 'issue-cert', changed: false, ...current }
  }

  fs.mkdirSync(current.paths.issuedDir, { recursive: true, mode: 0o700 })
  const tmpDir = fs.mkdtempSync(path.join(current.paths.issuedDir, '.tmp-'))
  const csrPath = path.join(tmpDir, 'request.csr')
  const extPath = path.join(tmpDir, 'extensions.cnf')
  const now = new Date()
  const createdAt = now.toISOString()
  const expiresAt = new Date(now.getTime() + Number(days || 7) * 24 * 60 * 60 * 1000).toISOString()
  try {
    fs.writeFileSync(extPath, [
      'basicConstraints=CA:FALSE',
      'keyUsage=digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      `subjectAltName=${tlsSubjectAltName(normalizedHost)}`,
      '',
    ].join('\n'))
    execFileSync(opensslPath(), [
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-subj',
      `/CN=${normalizedHost.replace(/[\\/]/g, ' ')}/O=Guard Local Development`,
      '-keyout',
      current.paths.privateKeyPath,
      '-out',
      csrPath,
    ], { stdio: 'ignore' })
    fs.chmodSync(current.paths.privateKeyPath, 0o600)
    execFileSync(opensslPath(), [
      'x509',
      '-req',
      '-in',
      csrPath,
      '-CA',
      ca.paths.certificatePath,
      '-CAkey',
      ca.paths.privateKeyPath,
      '-CAcreateserial',
      '-out',
      current.paths.certificatePath,
      '-days',
      String(days || 7),
      '-sha256',
      '-extfile',
      extPath,
    ], { stdio: 'ignore' })
    writeJsonFile(current.paths.metadataPath, {
      lifecycle: 'active',
      host: normalizedHost,
      subject: `CN=${normalizedHost}`,
      createdAt,
      expiresAt,
      days: Number(days || 7),
      caCertificatePath: ca.paths.certificatePath,
      installedGlobally: false,
      globalTrustManaged: false,
    })
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
  return { action: 'issue-cert', changed: true, ...tlsHostCertificateMetadata({ stateDir, host: normalizedHost }) }
}

const revokeTlsCa = ({ stateDir }) => {
  const current = tlsCaMetadata({ stateDir })
  fs.mkdirSync(current.paths.caDir, { recursive: true, mode: 0o700 })
  const previous = current.generated.metadata ? readJsonFile(current.paths.metadataPath) : {}
  const revokedAt = new Date().toISOString()
  writeJsonFile(current.paths.metadataPath, {
    ...previous,
    lifecycle: 'revoked',
    revokedAt,
    installedGlobally: false,
    globalTrustManaged: false,
  })
  return { action: 'revoke-ca', changed: previous.lifecycle !== 'revoked', ...tlsCaMetadata({ stateDir }) }
}

const routeName = (url, prefix) => {
  if (!url.pathname.startsWith(prefix)) return null
  const raw = url.pathname.slice(prefix.length)
  if (!raw || raw.includes('/')) return null
  try {
    const name = decodeURIComponent(raw)
    return isSafeName(name) ? name : null
  } catch {
    return null
  }
}

const routeNameWithAction = (url, prefix, action) => {
  if (!url.pathname.startsWith(prefix) || !url.pathname.endsWith(`/${action}`)) return null
  const raw = url.pathname.slice(prefix.length, -(`/${action}`.length))
  if (!raw || raw.includes('/')) return null
  try {
    const name = decodeURIComponent(raw)
    return isSafeName(name) ? name : null
  } catch {
    return null
  }
}

const handleReadEndpoint = (response, operation) => {
  try {
    operation()
  } catch (error) {
    writeJson(response, 500, { error: 'read_failed', message: error.message })
  }
}

const readRequestJson = (request) =>
  new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    request.on('data', (chunk) => {
      size += chunk.length
      if (size > 1024 * 1024) {
        reject(new Error('request body too large'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('error', reject)
    request.on('end', () => {
      if (chunks.length === 0) {
        resolve({})
        return
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new Error('invalid JSON request body'))
      }
    })
  })

const auditMutation = ({ tail, eventLogPath, operation, result }) => {
  const event = {
    schemaVersion: 1,
    at: new Date().toISOString(),
    type: 'policy.changed',
    backend: 'guardd',
    operation,
    profile: result.profile || '',
    template: result.template || '',
    field: result.field || '',
    changed: result.changed === true,
    ruleId: result.ruleId || '',
    metadataKey: result.metadataKey || '',
    path: result.path || '',
  }
  appendJsonLine(eventLogPath, event)
  tail.push(event)

  if (result.tlsChanged === true) {
    const tlsEvent = {
      schemaVersion: 1,
      at: new Date().toISOString(),
      type: 'tls.changed',
      backend: 'guardd',
      operation: result.action || operation,
      profile: result.profile || '',
      changed: true,
      path: result.path || '',
      before: result.before || null,
      after: result.after || null,
      globalTrustManaged: false,
    }
    appendJsonLine(eventLogPath, tlsEvent)
    tail.push(tlsEvent)
  }
}

const truncateEventLog = ({ eventLogPath, tail, keepBytes = 0 }) => {
  const parsedKeepBytes = Number.parseInt(String(keepBytes || 0), 10)
  if (!Number.isFinite(parsedKeepBytes) || parsedKeepBytes < 0) {
    throw new Error('keepBytes must be a non-negative integer')
  }
  if (parsedKeepBytes > DEFAULT_LOG_TRUNCATE_MAX_BYTES) {
    throw new Error(`keepBytes must be <= ${DEFAULT_LOG_TRUNCATE_MAX_BYTES}`)
  }

  fs.mkdirSync(path.dirname(eventLogPath), { recursive: true })
  const beforeBytes = fileSize(eventLogPath)
  let retained = Buffer.alloc(0)
  if (parsedKeepBytes > 0 && beforeBytes > 0) {
    const fd = fs.openSync(eventLogPath, 'r')
    try {
      const offset = Math.max(0, beforeBytes - parsedKeepBytes)
      const length = beforeBytes - offset
      const buffer = Buffer.alloc(length)
      fs.readSync(fd, buffer, 0, length, offset)
      if (offset > 0) {
        const firstNewline = buffer.indexOf(0x0a)
        retained = firstNewline === -1 ? Buffer.alloc(0) : buffer.subarray(firstNewline + 1)
      } else {
        retained = buffer
      }
    } finally {
      fs.closeSync(fd)
    }
  }
  fs.writeFileSync(eventLogPath, retained)
  tail.resetAfterLogRewrite()

  const event = {
    schemaVersion: 1,
    at: new Date().toISOString(),
    type: 'daemon.log.truncated',
    backend: 'guardd',
    operation: 'truncate-event-log',
    changed: beforeBytes !== retained.length,
    path: eventLogPath,
    beforeBytes,
    afterBytes: retained.length,
    keepBytes: parsedKeepBytes,
    maxKeepBytes: DEFAULT_LOG_TRUNCATE_MAX_BYTES,
  }
  appendJsonLine(eventLogPath, event)
  tail.push(event)
  tail.recordTruncation(event)
  return event
}

const parseMaybeDate = (value) => {
  if (!value) return null
  const ms = Date.parse(String(value))
  return Number.isFinite(ms) ? ms : null
}

const queryPersistedEvents = ({
  eventLogPath,
  limit = 100,
  type = '',
  host = '',
  profile = '',
  result = '',
  contains = '',
  since = '',
  maxBytes = DEFAULT_EVENT_QUERY_MAX_BYTES,
}) => {
  const parsedLimit = Math.min(parsePositiveInt(limit, 100), 1000)
  const parsedMaxBytes = Math.min(parsePositiveInt(maxBytes, DEFAULT_EVENT_QUERY_MAX_BYTES), DEFAULT_EVENT_QUERY_MAX_BYTES)
  const size = fileSize(eventLogPath)
  const offset = Math.max(0, size - parsedMaxBytes)
  const buffer = Buffer.alloc(Math.max(0, size - offset))
  if (buffer.length > 0) {
    const fd = fs.openSync(eventLogPath, 'r')
    try {
      fs.readSync(fd, buffer, 0, buffer.length, offset)
    } finally {
      fs.closeSync(fd)
    }
  }
  const lines = buffer.toString('utf8').split(/\r?\n/)
  if (offset > 0) lines.shift()
  const sinceMs = parseMaybeDate(since)
  const normalizedHost = String(host || '').toLowerCase()
  const normalizedProfile = String(profile || '')
  const normalizedResult = String(result || '')
  const normalizedContains = String(contains || '').toLowerCase()
  const events = []
  const resultSummary = {
    byType: {},
    byHost: {},
    byProfile: {},
    byResult: {},
  }
  let scanned = 0
  let invalid = 0
  let tamper = 0
  for (const line of lines) {
    if (!line.trim()) continue
    scanned += 1
    const classified = classifyEventLine(line)
    if (classified.invalidReason) {
      invalid += 1
      continue
    }
    if (classified.tamperReason) {
      tamper += 1
      continue
    }
    const event = classified.event
    if (type && event.type !== type) continue
    if (normalizedHost && String(event.host || '').toLowerCase() !== normalizedHost) continue
    if (normalizedProfile && String(event.profile || '') !== normalizedProfile) continue
    if (normalizedResult) {
      const eventResult = event.result || (typeof event.allowed === 'boolean' ? (event.allowed ? 'allow' : 'deny') : '')
      if (String(eventResult) !== normalizedResult) continue
    }
    if (sinceMs !== null) {
      const eventMs = parseMaybeDate(event.at)
      if (eventMs === null || eventMs < sinceMs) continue
    }
    if (normalizedContains && !JSON.stringify(event).toLowerCase().includes(normalizedContains)) continue
    events.push(event)
    incrementBucket(resultSummary.byType, event.type)
    incrementBucket(resultSummary.byHost, event.host)
    incrementBucket(resultSummary.byProfile, event.profile)
    incrementBucket(
      resultSummary.byResult,
      event.result || (typeof event.allowed === 'boolean' ? (event.allowed ? 'allow' : 'deny') : ''),
    )
  }
  return {
    path: eventLogPath,
    scannedEventCount: scanned,
    invalidLineCount: invalid,
    tamperLineCount: tamper,
    scannedBytes: buffer.length,
    truncatedScan: offset > 0,
    limit: parsedLimit,
    filters: {
      type: type || null,
      host: host || null,
      profile: profile || null,
      result: result || null,
      contains: contains || null,
      since: since || null,
    },
    summary: {
      matchedEventCount: events.length,
      returnedEventCount: Math.min(events.length, parsedLimit),
      byType: topBucketEntries(resultSummary.byType),
      byHost: topBucketEntries(resultSummary.byHost),
      byProfile: topBucketEntries(resultSummary.byProfile),
      byResult: topBucketEntries(resultSummary.byResult),
    },
    events: events.slice(-parsedLimit).reverse(),
  }
}

const checkEventLogIntegrity = ({ eventLogPath, maxBytes = DEFAULT_EVENT_QUERY_MAX_BYTES }) => {
  const parsedMaxBytes = Math.min(parsePositiveInt(maxBytes, DEFAULT_EVENT_QUERY_MAX_BYTES), DEFAULT_EVENT_QUERY_MAX_BYTES)
  const size = fileSize(eventLogPath)
  const offset = Math.max(0, size - parsedMaxBytes)
  const buffer = Buffer.alloc(Math.max(0, size - offset))
  let identity = null
  if (buffer.length > 0) {
    const fd = fs.openSync(eventLogPath, 'r')
    try {
      fs.readSync(fd, buffer, 0, buffer.length, offset)
      identity = statIdentity(fs.fstatSync(fd))
    } finally {
      fs.closeSync(fd)
    }
  } else if (fileExists(eventLogPath)) {
    identity = statIdentity(fs.statSync(eventLogPath))
  }

  const lines = buffer.toString('utf8').split(/\r?\n/)
  if (offset > 0) lines.shift()
  const schemaVersions = {}
  const issues = []
  const counters = {
    scannedLineCount: 0,
    validLineCount: 0,
    invalidLineCount: 0,
    tamperLineCount: 0,
  }
  let lineNumber = offset > 0 ? null : 0
  for (const line of lines) {
    if (lineNumber !== null) lineNumber += 1
    if (!line.trim()) continue
    counters.scannedLineCount += 1
    try {
      const raw = JSON.parse(line)
      incrementBucket(schemaVersions, raw?.schemaVersion)
    } catch {
      incrementBucket(schemaVersions, 'unparseable')
    }
    const classified = classifyEventLine(line)
    if (classified.invalidReason) {
      counters.invalidLineCount += 1
      if (issues.length < 20) {
        issues.push({ line: lineNumber, reason: classified.invalidReason, message: classified.message })
      }
      continue
    }
    if (classified.tamperReason) {
      counters.tamperLineCount += 1
      if (issues.length < 20) {
        issues.push({ line: lineNumber, reason: classified.tamperReason, message: classified.message })
      }
      continue
    }
    counters.validLineCount += 1
  }

  return {
    schemaVersion: EVENT_STORAGE_SCHEMA_VERSION,
    eventSchemaVersion: EVENT_LOG_SCHEMA_VERSION,
    path: eventLogPath,
    checkedAt: new Date().toISOString(),
    ok: counters.invalidLineCount === 0 && counters.tamperLineCount === 0,
    scannedBytes: buffer.length,
    totalBytes: size,
    truncatedScan: offset > 0,
    maxBytes: parsedMaxBytes,
    identity,
    digest: buffer.length > 0 ? `sha256:${crypto.createHash('sha256').update(buffer).digest('hex')}` : null,
    schemaVersions,
    ...counters,
    issues,
  }
}

const securityStatus = ({ stateDir, eventLogPath, policyStore, authState }) => {
  const ca = tlsCaMetadata({ stateDir })
  const token = authTokenMetadata(authState)
  const findings = []
  const checks = []
  const addCheck = ({ id, ok, severity = 'medium', message, path: targetPath = '' }) => {
    checks.push({ id, ok, severity, message, path: targetPath })
    if (!ok) findings.push({ id, severity, message, path: targetPath })
  }

  addCheck({
    id: 'api-token-required',
    ok: token.configured,
    severity: 'high',
    message: token.configured ? 'Mutating HTTP API requires a bearer token.' : 'Mutating HTTP API is not protected by a configured token.',
  })
  addCheck({
    id: 'api-token-strength',
    ok: !token.configured || token.length >= 20,
    severity: 'medium',
    message: token.configured
      ? `Configured API token length is ${token.length}; 20+ random characters are recommended.`
      : 'No API token configured.',
  })
  for (const [id, targetPath, expectedMask] of [
    ['state-dir-permissions', stateDir, 0o077],
    ['event-log-parent-permissions', path.dirname(eventLogPath), 0o022],
    ['policy-root-parent-permissions', policyStore.policyRoot, 0o022],
    ['daemon-state-file-permissions', path.join(stateDir, 'daemon-state.json'), 0o022],
    ['event-index-file-permissions', path.join(stateDir, 'event-index.json'), 0o022],
  ]) {
    const mode = fileMode(targetPath)
    addCheck({
      id,
      ok: mode === null || !modeAllowsGroupOrOther(mode, expectedMask),
      severity: id === 'state-dir-permissions' ? 'high' : 'medium',
      message: mode === null
        ? `${targetPath} does not exist yet.`
        : `${targetPath} mode is ${octalMode(mode)}.`,
      path: targetPath,
    })
  }
  addCheck({
    id: 'runtime-token-keychain-ready',
    ok: token.keychainDescriptor.ready === true || token.keychainDescriptor.enabled === false,
    severity: 'low',
    message: token.storage === 'macos-keychain'
      ? 'Runtime token is loaded from macOS Keychain.'
      : 'Runtime token can be persisted to macOS Keychain with /auth/token/persist or rotate persist=true.',
  })
  addCheck({
    id: 'tls-ca-key-private',
    ok: ca.privateKeyProtection.modeOk,
    severity: 'high',
    message: ca.generated.privateKey
      ? `TLS CA private key mode is ${ca.privateKeyProtection.actualMode}; expected 0600.`
      : 'TLS CA private key does not exist yet.',
    path: ca.paths.privateKeyPath,
  })
  addCheck({
    id: 'tls-ca-dir-private',
    ok: ca.privateKeyProtection.directoryModeOk,
    severity: 'high',
    message: ca.generated.caDir
      ? `TLS CA directory mode is ${ca.privateKeyProtection.directoryMode}; expected no group/other access.`
      : 'TLS CA directory does not exist yet.',
    path: ca.paths.caDir,
  })
  addCheck({
    id: 'tls-ca-keychain-ready',
    ok: ca.privateKeyProtection.keychainReady === true && ca.privateKeyProtection.keychainDescriptor.invokedByGuardd === false,
    severity: 'low',
    message: 'TLS CA key has a Keychain-ready descriptor; guardd does not invoke Keychain in this build.',
    path: ca.paths.privateKeyPath,
  })
  return {
    ok: findings.every((finding) => finding.severity !== 'high'),
    checkedAt: new Date().toISOString(),
    checks,
    findings,
    token,
    caKeyProtection: ca.privateKeyProtection,
    summary: {
      high: findings.filter((finding) => finding.severity === 'high').length,
      medium: findings.filter((finding) => finding.severity === 'medium').length,
      low: findings.filter((finding) => finding.severity === 'low').length,
    },
  }
}

const handleMutationEndpoint = async ({ request, response, tail, eventLogPath, operation }) => {
  try {
    const body = await readRequestJson(request)
    const result = await operation(body, request)
    auditMutation({ tail, eventLogPath, operation: result.action || 'mutate', result })
    writeJson(response, 200, result)
  } catch (error) {
    if (error.code === 'version_mismatch') {
      writeJson(response, error.statusCode || 412, {
        error: 'version_mismatch',
        message: error.message,
        expectedVersion: error.expectedVersion,
        currentVersion: error.currentVersion,
      })
      return
    }
    writeJson(response, 400, { error: 'mutation_failed', message: error.message })
  }
}

class PendingAlertQueue {
  constructor({ eventLogPath, tail, stateDir }) {
    this.eventLogPath = eventLogPath
    this.tail = tail
    this.stateDir = stateDir || resolveGuardStateDir()
    this.statePath = path.join(this.stateDir, 'pending-alerts.json')
    this.alerts = new Map()
    this.expiredCount = 0
    this.load()
  }

  load() {
    const state = safeReadJsonFile(this.statePath, null)
    if (!state || !Array.isArray(state.alerts)) return
    this.expiredCount = Number.isInteger(state.expiredCount) ? state.expiredCount : 0
    for (const alert of state.alerts) {
      if (!alert?.id) continue
      this.alerts.set(String(alert.id), alert)
    }
  }

  persist() {
    fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 })
    writeJsonFile(this.statePath, {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      expiredCount: this.expiredCount,
      alerts: Array.from(this.alerts.values()).sort((left, right) =>
        String(right.createdAt).localeCompare(String(left.createdAt)),
      ),
    })
  }

  emit(event) {
    appendJsonLine(this.eventLogPath, event)
    this.tail.push(event)
  }

  normalizeTimeout(body = {}) {
    const now = Date.now()
    if (body.expiresAt) {
      const expiresAtMs = Date.parse(String(body.expiresAt))
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now) throw new Error('expiresAt must be a future ISO timestamp')
      const timeoutMs = Math.min(expiresAtMs - now, MAX_ALERT_TIMEOUT_MS)
      return { timeoutMs, expiresAt: new Date(now + timeoutMs).toISOString() }
    }
    const requested = Number.parseInt(String(body.timeoutMs || DEFAULT_ALERT_TIMEOUT_MS), 10)
    const timeoutMs = Math.max(1, Math.min(Number.isFinite(requested) ? requested : DEFAULT_ALERT_TIMEOUT_MS, MAX_ALERT_TIMEOUT_MS))
    return { timeoutMs, expiresAt: new Date(now + timeoutMs).toISOString() }
  }

  create(body = {}) {
    const profile = String(body.profile || 'guard')
    const host = sanitizeTlsHost(body.host || '')
    if (!host) throw new Error('pending alert requires host')
    const now = new Date().toISOString()
    const { timeoutMs, expiresAt } = this.normalizeTimeout(body)
    const alert = {
      schemaVersion: 1,
      id: crypto.randomUUID(),
      type: 'guard.alert.pending',
      backend: 'guardd',
      status: 'pending',
      result: 'pending',
      createdAt: now,
      updatedAt: now,
      expiresAt,
      timeoutMs,
      profile,
      host,
      port: Number.isInteger(Number(body.port)) ? Number(body.port) : 0,
      method: String(body.method || ''),
      path: String(body.path || ''),
      protocol: String(body.protocol || ''),
      command: String(body.command || ''),
      projectDir: String(body.projectDir || ''),
      runDir: String(body.runDir || ''),
      reason: body.reason || 'pending-alert',
      suggestedAction: body.suggestedAction || '',
      suggestedDuration: body.suggestedDuration || '',
    }
    this.alerts.set(alert.id, alert)
    this.persist()
    this.emit({
      ...alert,
      at: now,
      operation: 'alert-pending',
    })
    return alert
  }

  expireDue(nowMs = Date.now()) {
    const expired = []
    for (const alert of this.alerts.values()) {
      if (alert.status !== 'pending') continue
      if (Date.parse(alert.expiresAt) > nowMs) continue
      const at = new Date().toISOString()
      alert.status = 'expired'
      alert.result = 'expired'
      alert.updatedAt = at
      alert.expiredAt = at
      this.expiredCount += 1
      expired.push(alert)
      this.persist()
      this.emit({
        ...alert,
        at,
        type: 'guard.alert.expired',
        operation: 'alert-expired',
        allowed: false,
      })
    }
    return expired
  }

  get(id) {
    this.expireDue()
    return this.alerts.get(String(id || '')) || null
  }

  list({ limit = 50, status = 'pending' } = {}) {
    this.expireDue()
    let alerts = Array.from(this.alerts.values())
    if (status) alerts = alerts.filter((alert) => alert.status === status)
    alerts.sort((left, right) => String(right.createdAt).localeCompare(String(left.createdAt)))
    const parsedLimit = parsePositiveInt(limit, 50)
    return {
      schemaVersion: 1,
      pendingCount: Array.from(this.alerts.values()).filter((alert) => alert.status === 'pending').length,
      expiredCount: this.expiredCount,
      totalCount: this.alerts.size,
      persisted: true,
      statePath: this.statePath,
      limit: parsedLimit,
      status: status || null,
      alerts: alerts.slice(0, parsedLimit),
    }
  }

  resolve({ id, decision }) {
    const alert = this.alerts.get(String(id || ''))
    if (!alert) {
      const error = new Error(`pending alert not found: ${id}`)
      error.code = 'alert_not_found'
      throw error
    }
    if (alert.status !== 'pending') {
      const error = new Error(`pending alert is ${alert.status}`)
      error.code = 'alert_not_pending'
      error.alert = alert
      throw error
    }
    const at = new Date().toISOString()
    alert.status = 'resolved'
    alert.result = decision.action
    alert.updatedAt = at
    alert.resolvedAt = at
    alert.decision = {
      action: decision.action,
      duration: decision.duration,
      rulePersisted: decision.rulePersisted === true,
      ruleId: decision.ruleId || '',
    }
    this.persist()
    this.emit({
      ...alert,
      at,
      type: 'guard.alert.resolved',
      operation: 'alert-resolved',
      allowed: decision.allowed === true,
      duration: decision.duration,
      rulePersisted: decision.rulePersisted === true,
      ruleId: decision.ruleId || '',
    })
    return alert
  }
}

const alertResolveId = (url) => {
  const match = url.pathname.match(/^\/alerts\/([^/]+)\/resolve$/)
  if (!match) return ''
  try {
    return decodeURIComponent(match[1])
  } catch {
    return ''
  }
}

const alertDecision = ({ body, policyStore, eventLogPath, tail }) => {
  const profile = String(body.profile || 'guard')
  const host = sanitizeTlsHost(body.host || '')
  const action = String(body.action || 'deny').toLowerCase()
  const duration = String(body.duration || 'once').toLowerCase()
  if (!['allow', 'deny'].includes(action)) throw new Error(`unsupported alert action: ${action}`)
  if (!['once', 'session', 'forever'].includes(duration)) throw new Error(`unsupported alert duration: ${duration}`)
  if (!host) throw new Error('alert decision requires host')
  const field = action === 'allow' ? 'network.allowedDomains' : 'network.deniedDomains'
  let mutation = null
  if (duration === 'forever') {
    mutation = policyStore.mutateArrayRule({
      profile,
      action: 'add',
      field,
      value: host,
      ifMatch: body.ifMatch || body.version || body.expectedVersion,
    })
  }
  const event = {
    schemaVersion: 1,
    at: new Date().toISOString(),
    type: 'guard.alert.decision',
    backend: 'guardd',
    profile,
    host,
    port: Number.isInteger(Number(body.port)) ? Number(body.port) : 0,
    alertId: body.alertId || '',
    resolvedAt: body.alertId ? new Date().toISOString() : '',
    expiresAt: body.expiresAt || '',
    method: body.method || '',
    path: body.path || '',
    action,
    duration,
    allowed: action === 'allow',
    rulePersisted: duration === 'forever',
    field: duration === 'forever' ? field : '',
    ruleId: mutation?.ruleId || '',
    version: mutation?.version || '',
    reason: body.reason || 'user-alert-decision',
  }
  appendJsonLine(eventLogPath, event)
  tail.push(event)
  return {
    action: 'alert-decision',
    changed: duration === 'forever',
    decision: event,
    mutation,
  }
}

const createServer = ({ tail, policyStore, startedAt, apiToken, eventLogPath, stateDir = resolveGuardStateDir() }) => {
  const authState = createAuthState(apiToken)
  const pendingAlerts = new PendingAlertQueue({ eventLogPath, tail, stateDir })
  return http.createServer(async (request, response) => {
    const url = new URL(request.url || '/', 'http://guardd.local')

    if (!isAuthorized(request, authState)) {
      response.setHeader('www-authenticate', 'Bearer realm="guardd"')
      writeJson(response, 401, { error: 'unauthorized' })
      return
    }

    const isMutation = request.method !== 'GET'
    if (isMutation && !authState.currentToken) {
      writeJson(response, 403, { error: 'api_token_required' })
      return
    }

    if (!['GET', 'POST'].includes(request.method)) {
      writeJson(response, 405, { error: 'method_not_allowed' })
      return
    }

    if (request.method === 'POST') {
      if (url.pathname === '/policy/evaluate') {
        try {
          const body = await readRequestJson(request)
          const profile = body.profile || url.searchParams.get('profile') || 'guard'
          const policy = policyStore.getEffectivePolicy(profile)
          if (!policy) {
            writeJson(response, 404, { error: 'profile_not_found', profile })
            return
          }
          writeJson(response, 200, {
            contractVersion: 1,
            profile,
            version: policy.effectiveVersion,
            request: {
              host: body.host || '',
              method: body.method || '',
              path: body.path || '',
            },
            decision: evaluateNetworkPolicy({
              config: policy.config,
              host: body.host,
              method: body.method,
              path: body.path,
            }),
          })
        } catch (error) {
          writeJson(response, 400, { error: 'evaluate_failed', message: error.message })
        }
        return
      }

      if (url.pathname === '/extension/sync') {
        try {
          const body = await readRequestJson(request)
          const result = body.action === 'invalidate'
            ? invalidateExtensionSync({ stateDir, reason: body.reason || 'manual-invalidation' })
            : writeExtensionSync({
                stateDir,
                policyStore,
                eventLogPath,
                profile: body.profile || 'guard',
                mode: body.mode || 'permissive-fallback',
              })
          const event = {
            schemaVersion: 1,
            at: new Date().toISOString(),
            type: 'network.extension.sync',
            backend: 'guardd',
            operation: result.action,
            profile: result.profile || body.profile || 'guard',
            sequence: result.sequence,
            path: result.paths.manifestPath,
            invalidated: result.invalidated === true,
          }
          appendJsonLine(eventLogPath, event)
          tail.push(event)
          writeJson(response, 200, result)
        } catch (error) {
          writeJson(response, error.code === 'profile_not_found' ? 404 : 400, { error: 'extension_sync_failed', message: error.message })
        }
        return
      }

      if (url.pathname === '/auth/token/rotate') {
        try {
          const body = await readRequestJson(request)
          const result = rotateRuntimeToken({ authState, request, body })
          const event = {
            schemaVersion: 1,
            at: new Date().toISOString(),
            type: 'daemon.auth.token.rotated',
            backend: 'guardd',
            operation: result.action,
            changed: true,
            previousFingerprint: result.previousFingerprint,
            fingerprint: result.auth.fingerprint,
            persistsAcrossRestart: false,
          }
          appendJsonLine(eventLogPath, event)
          tail.push(event)
          writeJson(response, 200, result)
        } catch (error) {
          writeJson(response, error.code === 'token_not_configured' ? 409 : 400, {
            error: error.code || 'token_rotation_failed',
            message: error.message,
          })
        }
        return
      }

      if (url.pathname === '/auth/token/persist') {
        try {
          const result = persistRuntimeToken({ authState })
          const event = {
            schemaVersion: 1,
            at: new Date().toISOString(),
            type: 'daemon.auth.token.persisted',
            backend: 'guardd',
            operation: result.action,
            changed: true,
            fingerprint: result.auth.fingerprint,
            storage: result.auth.storage,
          }
          appendJsonLine(eventLogPath, event)
          tail.push(event)
          writeJson(response, 200, result)
        } catch (error) {
          writeJson(response, error.code === 'token_not_configured' ? 409 : 400, {
            error: error.code || 'token_persist_failed',
            message: error.message,
          })
        }
        return
      }

      if (url.pathname === '/tls/ca') {
        try {
          const body = await readRequestJson(request)
          const action = body.action || 'generate'
          const result = action === 'rotate'
            ? generateTlsCa({ stateDir, rotate: true, days: body.days || 30, commonName: body.commonName || undefined })
            : action === 'revoke'
              ? revokeTlsCa({ stateDir })
              : generateTlsCa({ stateDir, rotate: false, days: body.days || 30, commonName: body.commonName || undefined })
          const event = {
            schemaVersion: 1,
            at: new Date().toISOString(),
            type: 'tls.ca.changed',
            backend: 'guardd',
            operation: result.action,
            changed: result.changed === true,
            lifecycle: result.lifecycle,
            path: result.paths.certificatePath,
            globalTrustManaged: false,
          }
          appendJsonLine(eventLogPath, event)
          tail.push(event)
          writeJson(response, 200, result)
        } catch (error) {
          writeJson(response, 400, { error: 'tls_ca_failed', message: error.message })
        }
        return
      }

      if (url.pathname === '/tls/cert') {
        try {
          const body = await readRequestJson(request)
          const result = issueTlsHostCertificate({
            stateDir,
            host: body.host,
            days: body.days || 7,
            force: body.force === true,
          })
          const event = {
            schemaVersion: 1,
            at: new Date().toISOString(),
            type: 'tls.cert.changed',
            backend: 'guardd',
            operation: result.action,
            changed: result.changed === true,
            host: result.host,
            lifecycle: result.lifecycle,
            path: result.paths.certificatePath,
            caCertificatePath: result.paths.caCertificatePath,
            globalTrustManaged: false,
          }
          appendJsonLine(eventLogPath, event)
          tail.push(event)
          writeJson(response, 200, result)
        } catch (error) {
          writeJson(response, error.code === 'ca_missing' ? 409 : 400, { error: 'tls_cert_failed', message: error.message })
        }
        return
      }

      if (url.pathname === '/events/truncate') {
        try {
          const body = await readRequestJson(request)
          const result = truncateEventLog({
            eventLogPath,
            tail,
            keepBytes: body.keepBytes ?? 0,
          })
          writeJson(response, 200, result)
        } catch (error) {
          writeJson(response, 400, { error: 'truncate_failed', message: error.message })
        }
        return
      }

      if (url.pathname === '/alerts/pending') {
        try {
          const body = await readRequestJson(request)
          const alert = pendingAlerts.create(body)
          writeJson(response, 201, {
            action: 'alert-pending',
            changed: true,
            alert,
            pending: pendingAlerts.list({ limit: 50 }),
          })
        } catch (error) {
          writeJson(response, 400, { error: 'alert_pending_failed', message: error.message })
        }
        return
      }

      const resolveAlertId = alertResolveId(url)
      if (resolveAlertId) {
        try {
          const body = await readRequestJson(request)
          const pending = pendingAlerts.get(resolveAlertId)
          if (!pending) {
            writeJson(response, 404, { error: 'alert_not_found', alertId: resolveAlertId })
            return
          }
          const result = alertDecision({
            body: {
              ...body,
              alertId: resolveAlertId,
              profile: body.profile || pending.profile,
              host: body.host || pending.host,
              port: body.port ?? pending.port,
              method: body.method || pending.method,
              path: body.path || pending.path,
              expiresAt: pending.expiresAt,
              reason: body.reason || 'pending-alert-resolved',
            },
            policyStore,
            eventLogPath,
            tail,
          })
          const alert = pendingAlerts.resolve({ id: resolveAlertId, decision: result.decision })
          writeJson(response, 200, {
            ...result,
            action: 'alert-resolve',
            alert,
            pending: pendingAlerts.list({ limit: 50 }),
          })
        } catch (error) {
          if (error.code === 'version_mismatch') {
            writeJson(response, error.statusCode || 412, {
              error: 'version_mismatch',
              message: error.message,
              expectedVersion: error.expectedVersion,
              currentVersion: error.currentVersion,
            })
            return
          }
          const status = error.code === 'alert_not_pending' ? 409 : 400
          writeJson(response, status, { error: error.code || 'alert_resolve_failed', message: error.message, alert: error.alert || null })
        }
        return
      }

      if (url.pathname === '/alerts/decision') {
        try {
          const body = await readRequestJson(request)
          if (body.alertId) {
            const pending = pendingAlerts.get(body.alertId)
            if (!pending) {
              writeJson(response, 404, { error: 'alert_not_found', alertId: body.alertId })
              return
            }
            if (pending.status !== 'pending') {
              writeJson(response, 409, { error: 'alert_not_pending', message: `pending alert is ${pending.status}`, alert: pending })
              return
            }
          }
          const result = alertDecision({ body, policyStore, eventLogPath, tail })
          if (body.alertId) {
            const alert = pendingAlerts.resolve({ id: body.alertId, decision: result.decision })
            writeJson(response, 200, { ...result, alert, pending: pendingAlerts.list({ limit: 50 }) })
          } else {
            writeJson(response, 200, result)
          }
        } catch (error) {
          if (error.code === 'version_mismatch') {
            writeJson(response, error.statusCode || 412, {
              error: 'version_mismatch',
              message: error.message,
              expectedVersion: error.expectedVersion,
              currentVersion: error.currentVersion,
            })
            return
          }
          const status = error.code === 'alert_not_found' ? 404 : error.code === 'alert_not_pending' ? 409 : 400
          writeJson(response, status, { error: error.code || 'alert_decision_failed', message: error.message, alert: error.alert || null })
        }
        return
      }

      const ruleProfile = routeNameWithAction(url, '/profiles/', 'rules')
      if (ruleProfile) {
        await handleMutationEndpoint({
          request,
          response,
          tail,
          eventLogPath,
          operation: (body, mutationRequest) => {
            const action = body.action || 'add'
            if (body.field === 'network.httpRules' || body.rule) {
              return policyStore.mutateHttpRule({
                profile: ruleProfile,
                action,
                rule: body.rule || body.value,
                disabled: body.disabled === true,
                ifMatch: readIfMatch(mutationRequest, body),
              })
            }
            return policyStore.mutateArrayRule({
              profile: ruleProfile,
              action,
              field: body.field,
              value: String(body.value ?? ''),
              disabled: body.disabled === true,
              ifMatch: readIfMatch(mutationRequest, body),
            })
          },
        })
        return
      }

      const tlsProfile = routeNameWithAction(url, '/profiles/', 'tls')
      if (tlsProfile) {
        await handleMutationEndpoint({
          request,
          response,
          tail,
          eventLogPath,
          operation: (body, mutationRequest) => policyStore.mutateTls({
            profile: tlsProfile,
            enabled: body.enabled !== false,
            ifMatch: readIfMatch(mutationRequest, body),
          }),
        })
        return
      }

      const previewTemplateName = routeNameWithAction(url, '/templates/', 'preview')
      if (previewTemplateName) {
        try {
          const body = await readRequestJson(request)
          const preview = policyStore.previewTemplate({
            template: previewTemplateName,
            profile: body.profile || 'guard',
          })
          response.setHeader('etag', `"${preview.templateVersion}"`)
          writeJson(response, 200, preview)
        } catch (error) {
          writeJson(response, 400, { error: 'preview_failed', message: error.message })
        }
        return
      }

      const applyTemplateName = routeNameWithAction(url, '/templates/', 'apply')
      if (applyTemplateName) {
        await handleMutationEndpoint({
          request,
          response,
          tail,
          eventLogPath,
          operation: (body, mutationRequest) => policyStore.applyTemplate({
            template: applyTemplateName,
            profile: body.profile || 'guard',
            force: body.force === true,
            ifMatch: readIfMatch(mutationRequest, body),
          }),
        })
        return
      }

      writeJson(response, 404, { error: 'not_found' })
      return
    }

    if (url.pathname === '/health') {
      const state = daemonStatePayload({ tail, policyStore, startedAt, authState, stateDir, eventLogPath })
      writeJson(response, 200, {
        ...state,
        eventLogPath: state.paths.eventLogPath,
        policyRoot: state.paths.policyRoot,
        repoRoot: state.paths.repoRoot,
        stateDir: state.paths.stateDir,
        authRequired: state.auth.required,
        retainedEventCount: state.tail.retainedEventCount,
        invalidLineCount: state.tail.invalidLineCount,
        tamperLineCount: state.tail.tamperLineCount,
        lastReadAt: state.tail.lastReadAt,
        lastPersistedAt: state.tail.lastPersistedAt,
        readError: state.tail.readError,
        eventCursorOffset: state.tail.offset,
        stateMetadataPath: state.tail.metadataPath,
        recovery: state.tail.recovery,
        retention: state.tail.retention,
        index: state.tail.index,
      })
      return
    }

    if (url.pathname === '/state') {
      writeJson(response, 200, daemonStatePayload({ tail, policyStore, startedAt, authState, stateDir, eventLogPath }))
      return
    }

    if (url.pathname === '/auth/token') {
      writeJson(response, 200, authTokenMetadata(authState))
      return
    }

    if (url.pathname === '/tls/ca') {
      writeJson(response, 200, tlsCaMetadata({ stateDir }))
      return
    }

    if (url.pathname === '/tls/cert') {
      try {
        writeJson(response, 200, tlsHostCertificateMetadata({
          stateDir,
          host: url.searchParams.get('host') || '',
        }))
      } catch (error) {
        writeJson(response, 400, { error: 'tls_cert_failed', message: error.message })
      }
      return
    }

    if (url.pathname === '/tls/status') {
      writeJson(response, 200, tlsTrustStatus({ stateDir }))
      return
    }

    if (url.pathname === '/security/status') {
      writeJson(response, 200, securityStatus({ stateDir, eventLogPath, policyStore, authState }))
      return
    }

    if (url.pathname === '/extension/sync') {
      writeJson(response, 200, extensionSyncState({ stateDir }))
      return
    }

    if (url.pathname === '/events') {
      const limit = parsePositiveInt(url.searchParams.get('limit'), 100)
      const type = url.searchParams.get('type') || ''
      writeJson(response, 200, {
        path: tail.eventLogPath,
        retainedEventCount: tail.events.length,
        invalidLineCount: tail.invalidLineCount,
        tamperLineCount: tail.tamperLineCount,
        limit,
        type: type || null,
        events: tail.recent({ limit, type }),
      })
      return
    }

    if (url.pathname === '/events/index') {
      writeJson(response, 200, tail.index.payload())
      return
    }

    if (url.pathname === '/events/integrity') {
      try {
        writeJson(response, 200, checkEventLogIntegrity({
          eventLogPath,
          maxBytes: url.searchParams.get('maxBytes') || DEFAULT_EVENT_QUERY_MAX_BYTES,
        }))
      } catch (error) {
        writeJson(response, 400, { error: 'event_integrity_failed', message: error.message })
      }
      return
    }

    if (url.pathname === '/alerts/pending') {
      writeJson(response, 200, pendingAlerts.list({
        limit: url.searchParams.get('limit') || 50,
        status: url.searchParams.get('status') || 'pending',
      }))
      return
    }

    if (url.pathname === '/alerts') {
      writeJson(response, 200, queryPersistedEvents({
        eventLogPath,
        limit: url.searchParams.get('limit') || 50,
        type: 'guard.alert.decision',
        host: url.searchParams.get('host') || '',
        profile: url.searchParams.get('profile') || '',
        result: '',
        contains: url.searchParams.get('contains') || '',
        since: url.searchParams.get('since') || '',
        maxBytes: url.searchParams.get('maxBytes') || DEFAULT_EVENT_QUERY_MAX_BYTES,
      }))
      return
    }

    if (url.pathname === '/events/query') {
      try {
        writeJson(response, 200, queryPersistedEvents({
          eventLogPath,
          limit: url.searchParams.get('limit') || 100,
          type: url.searchParams.get('type') || '',
          host: url.searchParams.get('host') || '',
          profile: url.searchParams.get('profile') || '',
          result: url.searchParams.get('result') || '',
          contains: url.searchParams.get('contains') || '',
          since: url.searchParams.get('since') || '',
          maxBytes: url.searchParams.get('maxBytes') || DEFAULT_EVENT_QUERY_MAX_BYTES,
        }))
      } catch (error) {
        writeJson(response, 400, { error: 'event_query_failed', message: error.message })
      }
      return
    }

    if (url.pathname === '/policy') {
      handleReadEndpoint(response, () => {
        const profile = url.searchParams.get('profile') || 'guard'
        const policy = policyStore.getEffectivePolicy(profile)
        if (!policy) {
          writeJson(response, 404, { error: 'profile_not_found', profile })
          return
        }
        response.setHeader('etag', `"${policy.version}"`)
        writeJson(response, 200, {
          policyRoot: policyStore.policyRoot,
          repoRoot: policyStore.repoRoot,
          profile,
          effective: true,
          ...policy,
        })
      })
      return
    }

    if (url.pathname === '/profiles') {
      handleReadEndpoint(response, () => {
        writeJson(response, 200, {
          policyRoot: policyStore.policyRoot,
          projectProfilesDir: policyStore.projectProfilesDir,
          builtinProfilesDir: policyStore.builtinProfilesDir,
          profiles: policyStore.listProfiles(),
        })
      })
      return
    }

    const profileName = routeName(url, '/profiles/')
    if (profileName) {
      handleReadEndpoint(response, () => {
        const profile = policyStore.getProfile(profileName)
        if (!profile) {
          writeJson(response, 404, { error: 'profile_not_found', profile: profileName })
          return
        }
        response.setHeader('etag', `"${profile.version}"`)
        writeJson(response, 200, profile)
      })
      return
    }

    if (url.pathname === '/templates') {
      handleReadEndpoint(response, () => {
        writeJson(response, 200, {
          repoRoot: policyStore.repoRoot,
          templatesDir: policyStore.templatesDir,
          templates: policyStore.listTemplates(),
        })
      })
      return
    }

    const previewTemplateName = routeNameWithAction(url, '/templates/', 'preview')
    if (previewTemplateName) {
      handleReadEndpoint(response, () => {
        const profile = url.searchParams.get('profile') || 'guard'
        const preview = policyStore.previewTemplate({ template: previewTemplateName, profile })
        response.setHeader('etag', `"${preview.templateVersion}"`)
        writeJson(response, 200, preview)
      })
      return
    }

    const templateName = routeName(url, '/templates/')
    if (templateName) {
      handleReadEndpoint(response, () => {
        const template = policyStore.getTemplate(templateName)
        if (!template) {
          writeJson(response, 404, { error: 'template_not_found', template: templateName })
          return
        }
        response.setHeader('etag', `"${template.version}"`)
        writeJson(response, 200, template)
      })
      return
    }

    writeJson(response, 404, { error: 'not_found' })
  })
}

const main = () => {
  let config
  try {
    config = parseArgs(process.argv.slice(2))
  } catch (error) {
    console.error(`guardd: ${error.message}`)
    console.error(usage())
    process.exit(2)
  }

  if (config.help) {
    process.stdout.write(usage())
    process.exit(0)
  }

  if (!isLoopbackHost(config.host) && !config.apiToken) {
    console.error('guardd: --api-token is required when listening outside loopback')
    process.exit(2)
  }

  const tail = new EventTail(config)
  const policyStore = new PolicyStore(config)
  const server = createServer({
    tail,
    policyStore,
    startedAt: new Date().toISOString(),
    apiToken: config.apiToken,
    eventLogPath: config.eventLogPath,
    stateDir: config.stateDir,
  })

  tail.start()
  server.listen(config.port, config.host, () => {
    const address = server.address()
    const port = typeof address === 'object' && address ? address.port : config.port
    console.error(`guardd: listening on http://${config.host}:${port}`)
    console.error(`guardd: tailing ${config.eventLogPath}`)
    console.error(`guardd: policy root ${config.policyRoot}`)
    if (config.apiToken) console.error('guardd: HTTP API token authentication enabled')
  })

  const shutdown = () => {
    tail.stop()
    tail.persist()
    server.close(() => process.exit(0))
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main()
}

export { EventTail, createServer, parseArgs, resolveGuardEventLogPath, resolveGuardStateDir }
