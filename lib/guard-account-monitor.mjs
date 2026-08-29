import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { globToRegex } from './guard-utils.mjs'

export const ACCOUNT_SNAPSHOT_VERSION = 1
export const ACCOUNT_MONITORING_VERSION = 1
export const ACCOUNT_STATES = new Set([
  'signedIn',
  'signedOut',
  'expired',
  'unavailable',
  'error',
  'unknown',
])

const DEFAULT_PASSIVE_INTERVAL_SECONDS = 60
const DEFAULT_EXPIRY_WARNING_SECONDS = 30 * 60
const DEFAULT_TIMEOUT_MS = 5000
const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
const DEFAULT_MAX_GLOB_MATCHES = 10_000
const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const SHELL_BASENAMES = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh'])
const SECRET_ENV_KEY = /(?:token|secret|password|api[_-]?key|credential)/i
const SAFE_INHERITED_ENV = [
  'HOME',
  'PATH',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TMPDIR',
  'USER',
  'LOGNAME',
  'SHELL',
  'SSH_AUTH_SOCK',
  'TERM',
]

const plainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

export const expandHome = (value, env = process.env) => {
  if (typeof value !== 'string') return value
  const home = env.HOME || os.homedir()
  if (value === '~') return home
  return value.startsWith('~/') ? path.join(home, value.slice(2)) : value
}

export const resolveGuardUserConfigPath = (env = process.env) => {
  if (env.GUARD_CONFIG_DIR) return path.join(path.resolve(expandHome(env.GUARD_CONFIG_DIR, env)), 'config.json')
  if (env.XDG_CONFIG_HOME) return path.join(path.resolve(expandHome(env.XDG_CONFIG_HOME, env)), 'guard', 'config.json')
  const home = env.HOME || os.homedir()
  return path.join(home, '.config', 'guard', 'config.json')
}

export const resolveAccountStatePath = (stateDir) => path.join(stateDir, 'account-sessions.json')

const boundedInteger = (value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) => {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback
}

const isoTimestamp = (value) => {
  if (value === null || value === undefined || value === '') return ''
  const date = value instanceof Date ? value : new Date(value)
  return Number.isFinite(date.getTime()) ? date.toISOString() : ''
}

const getPointer = (value, pointer) => {
  if (pointer === '' || pointer === '/') return value
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) return undefined
  let current = value
  for (const raw of pointer.slice(1).split('/')) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~')
    if ((plainObject(current) || Array.isArray(current)) && Object.prototype.hasOwnProperty.call(current, key)) {
      current = current[key]
    } else {
      return undefined
    }
  }
  return current
}

const dottedValue = (value, dotted) => {
  let current = value
  for (const key of String(dotted || '').split('.').filter(Boolean)) {
    if (!plainObject(current) || !Object.prototype.hasOwnProperty.call(current, key)) return undefined
    current = current[key]
  }
  return current
}

const normalizeTarget = (target = {}, errors, prefix) => {
  const type = String(target.type || 'host')
  if (!['host', 'docker'].includes(type)) errors.push(`${prefix}.type must be host or docker`)
  if (type === 'docker' && !String(target.container || '').trim()) {
    errors.push(`${prefix}.container is required for docker targets`)
  }
  const environment = plainObject(target.environment)
    ? Object.fromEntries(Object.entries(target.environment).map(([key, value]) => [String(key), String(value)]))
    : {}
  if (Object.keys(environment).some((key) => SECRET_ENV_KEY.test(key))) {
    errors.push(`${prefix}.environment must not configure credential-bearing values`)
  }
  return {
    type,
    label: String(target.label || (type === 'docker' ? target.container || 'Docker' : 'This Mac')),
    ...(type === 'docker'
      ? {
          dockerPath: String(target.dockerPath || '/usr/local/bin/docker'),
          container: String(target.container || ''),
          user: String(target.user || ''),
        }
      : {}),
    environment,
  }
}

const validateArgv = (argv, errors, warnings, prefix) => {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((entry) => typeof entry !== 'string' || !entry)) {
    errors.push(`${prefix}.argv must be a non-empty string array`)
    return []
  }
  if (SHELL_BASENAMES.has(path.basename(argv[0]))) {
    warnings.push(`${prefix}.argv explicitly invokes a shell; review it as executable user configuration`)
  }
  if (argv.some((entry) => /(?:--?(?:token|secret|password|api[-_]?key)(?:=|$))/i.test(entry))) {
    errors.push(`${prefix}.argv must not contain credential-bearing flags`)
  }
  return argv.map(String)
}

const validateExtract = (extract, errors, prefix) => {
  if (!plainObject(extract)) return {}
  const result = {}
  for (const [field, spec] of Object.entries(extract)) {
    if (!['identity', 'expiresAt', 'lastUsedAt'].includes(field)) {
      errors.push(`${prefix}.${field} is not an allowlisted snapshot field`)
      continue
    }
    if (!plainObject(spec)) {
      errors.push(`${prefix}.${field} must be an object`)
      continue
    }
    const source = String(spec.source || 'json')
    if (!['json', 'stdout'].includes(source)) {
      errors.push(`${prefix}.${field}.source must be json or stdout`)
      continue
    }
    if (source === 'json') {
      if (typeof spec.pointer !== 'string' || !spec.pointer.startsWith('/')) {
        errors.push(`${prefix}.${field}.pointer must be a JSON Pointer`)
        continue
      }
      result[field] = {
        source,
        pointer: spec.pointer,
        omitValues: Array.isArray(spec.omitValues) ? spec.omitValues.map(String) : [],
      }
    } else {
      try {
        if (!spec.regex) throw new Error('missing regex')
        new RegExp(spec.regex, spec.flags || '')
        result[field] = {
          source,
          regex: String(spec.regex),
          flags: String(spec.flags || ''),
          group: boundedInteger(spec.group, 1, { min: 0, max: 20 }),
        }
      } catch {
        errors.push(`${prefix}.${field}.regex must be valid`)
      }
    }
  }
  return result
}

const normalizeStateRules = (rules, errors, prefix) => {
  if (rules === undefined) return []
  if (!Array.isArray(rules)) {
    errors.push(`${prefix} must be an array`)
    return []
  }
  return rules.map((rule, index) => {
    const itemPrefix = `${prefix}[${index}]`
    if (!plainObject(rule)) {
      errors.push(`${itemPrefix} must be an object`)
      return null
    }
    const state = String(rule.state || '')
    if (!ACCOUNT_STATES.has(state)) errors.push(`${itemPrefix}.state is invalid`)
    const normalized = { state }
    if (rule.exitCode !== undefined) normalized.exitCode = Number(rule.exitCode)
    if (rule.stdoutMatches !== undefined) {
      try {
        new RegExp(rule.stdoutMatches, rule.flags || '')
        normalized.stdoutMatches = String(rule.stdoutMatches)
        normalized.flags = String(rule.flags || '')
      } catch {
        errors.push(`${itemPrefix}.stdoutMatches must be a valid regex`)
      }
    }
    if (rule.pointer !== undefined) {
      if (typeof rule.pointer !== 'string' || !rule.pointer.startsWith('/')) {
        errors.push(`${itemPrefix}.pointer must be a JSON Pointer`)
      } else {
        normalized.pointer = rule.pointer
        if (Object.prototype.hasOwnProperty.call(rule, 'equals')) normalized.equals = rule.equals
        if (Object.prototype.hasOwnProperty.call(rule, 'exists')) normalized.exists = Boolean(rule.exists)
      }
    }
    return normalized
  }).filter(Boolean)
}

const normalizeProbe = (probe, errors, warnings, prefix) => {
  if (!plainObject(probe)) {
    errors.push(`${prefix} must be an object`)
    return { type: 'command', argv: [] }
  }
  const type = String(probe.type || 'command')
  if (!['command', 'jsonFiles', 'latestMtime', 'guardEvents'].includes(type)) {
    errors.push(`${prefix}.type is unsupported`)
  }
  const common = {
    type,
    label: String(probe.label || ''),
    timeoutMs: boundedInteger(probe.timeoutMs, DEFAULT_TIMEOUT_MS, { min: 100, max: 60_000 }),
    maxOutputBytes: boundedInteger(probe.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES, { min: 1024, max: DEFAULT_MAX_OUTPUT_BYTES }),
  }
  if (probe.timeoutMs !== undefined && common.timeoutMs !== Number(probe.timeoutMs)) {
    errors.push(`${prefix}.timeoutMs must be between 100 and 60000`)
  }
  if (type === 'command') {
    return {
      ...common,
      argv: validateArgv(probe.argv, errors, warnings, prefix),
      cwd: probe.cwd ? String(probe.cwd) : '',
      environment: plainObject(probe.environment)
        ? Object.fromEntries(Object.entries(probe.environment).map(([key, value]) => [String(key), String(value)]))
        : {},
      parseJson: probe.parseJson === true,
    }
  }
  if (type === 'jsonFiles' || type === 'latestMtime') {
    if (!Array.isArray(probe.paths) || probe.paths.length === 0 || probe.paths.some((entry) => typeof entry !== 'string')) {
      errors.push(`${prefix}.paths must be a non-empty string array`)
    }
    const result = {
      ...common,
      paths: Array.isArray(probe.paths) ? probe.paths.map(String) : [],
      sourceLabel: String(probe.sourceLabel || probe.label || (type === 'jsonFiles' ? 'credential cache' : 'local files')),
    }
    if (type === 'jsonFiles') {
      result.choose = probe.choose === 'latestMtime' ? 'latestMtime' : 'latestExpiry'
      result.match = plainObject(probe.match) ? structuredClone(probe.match) : {}
      for (const pointer of Object.keys(result.match)) {
        if (!pointer.startsWith('/')) errors.push(`${prefix}.match keys must be JSON Pointers`)
      }
    }
    return result
  }
  return {
    ...common,
    match: plainObject(probe.match) ? structuredClone(probe.match) : {},
    timestampFields: Array.isArray(probe.timestampFields) && probe.timestampFields.length > 0
      ? probe.timestampFields.map(String)
      : ['at', 'timestamp', 'time'],
    sourceLabel: String(probe.sourceLabel || probe.label || 'Guard events'),
  }
}

export const validateAccountMonitoringConfig = (raw = {}) => {
  const errors = []
  const warnings = []
  if (!plainObject(raw)) return { errors: ['accountMonitoring must be an object'], warnings, config: null }
  const schemaVersion = Number(raw.schemaVersion ?? ACCOUNT_MONITORING_VERSION)
  if (schemaVersion !== ACCOUNT_MONITORING_VERSION) errors.push(`unsupported accountMonitoring.schemaVersion: ${schemaVersion}`)
  if (!Array.isArray(raw.monitors)) errors.push('accountMonitoring.monitors must be an array')
  const seen = new Set()
  const monitors = (Array.isArray(raw.monitors) ? raw.monitors : []).map((monitor, index) => {
    const prefix = `accountMonitoring.monitors[${index}]`
    if (!plainObject(monitor)) {
      errors.push(`${prefix} must be an object`)
      return null
    }
    const id = String(monitor.id || '')
    if (!SAFE_ID.test(id)) errors.push(`${prefix}.id must match ${SAFE_ID}`)
    if (seen.has(id)) errors.push(`${prefix}.id is duplicated: ${id}`)
    seen.add(id)
    const target = normalizeTarget(monitor.target, errors, `${prefix}.target`)
    if (monitor.expiryWarningSeconds !== undefined) {
      const value = Number(monitor.expiryWarningSeconds)
      if (!Number.isInteger(value) || value < 0 || value > 365 * 24 * 3600) {
        errors.push(`${prefix}.expiryWarningSeconds must be between 0 and 31536000`)
      }
    }
    const status = plainObject(monitor.status) ? monitor.status : {}
    const cadence = String(status.cadence || 'passive')
    if (!['passive', 'manual'].includes(cadence)) errors.push(`${prefix}.status.cadence must be passive or manual`)
    const login = plainObject(monitor.login) ? monitor.login : null
    if (login?.stdin !== undefined || login?.withStdin === true) {
      errors.push(`${prefix}.login must not configure stdin or secret input`)
    }
    if (login && String(login.presentation || 'terminal') !== 'terminal') {
      errors.push(`${prefix}.login.presentation must be terminal`)
    }
    if (plainObject(login?.environment) && Object.keys(login.environment).some((key) => SECRET_ENV_KEY.test(key))) {
      errors.push(`${prefix}.login.environment must not configure credential-bearing values`)
    }
    return {
      id,
      label: String(monitor.label || id),
      providerLabel: String(monitor.providerLabel || ''),
      enabled: monitor.enabled !== false,
      target,
      expiryWarningSeconds: monitor.expiryWarningSeconds === undefined
        ? null
        : boundedInteger(monitor.expiryWarningSeconds, 0, { min: 0, max: 365 * 24 * 3600 }),
      status: {
        cadence,
        activitySourceLabel: String(status.activitySourceLabel || ''),
        probe: normalizeProbe(status.probe, errors, warnings, `${prefix}.status.probe`),
        stateRules: normalizeStateRules(status.stateRules, errors, `${prefix}.status.stateRules`),
        extract: validateExtract(status.extract, errors, `${prefix}.status.extract`),
      },
      activity: (Array.isArray(monitor.activity) ? monitor.activity : []).map((probe, activityIndex) =>
        normalizeProbe(probe, errors, warnings, `${prefix}.activity[${activityIndex}]`),
      ),
      login: login
        ? {
            presentation: String(login.presentation || 'terminal'),
            argv: validateArgv(login.argv, errors, warnings, `${prefix}.login`),
            cwd: login.cwd ? String(login.cwd) : '',
            environment: plainObject(login.environment)
              ? Object.fromEntries(Object.entries(login.environment).map(([key, value]) => [String(key), String(value)]))
              : {},
          }
        : null,
    }
  }).filter(Boolean)
  const config = {
    schemaVersion,
    enabled: raw.enabled !== false,
    passiveIntervalSeconds: boundedInteger(raw.passiveIntervalSeconds, DEFAULT_PASSIVE_INTERVAL_SECONDS, { min: 10, max: 24 * 3600 }),
    expiryWarningSeconds: boundedInteger(raw.expiryWarningSeconds, DEFAULT_EXPIRY_WARNING_SECONDS, { min: 0, max: 365 * 24 * 3600 }),
    monitors,
  }
  for (const monitor of config.monitors) {
    if (monitor.expiryWarningSeconds === null) monitor.expiryWarningSeconds = config.expiryWarningSeconds
    monitor.staleAfterSeconds = Math.max(120, config.passiveIntervalSeconds * 2)
  }
  if (raw.passiveIntervalSeconds !== undefined && config.passiveIntervalSeconds !== Number(raw.passiveIntervalSeconds)) {
    errors.push('accountMonitoring.passiveIntervalSeconds must be between 10 and 86400')
  }
  if (raw.expiryWarningSeconds !== undefined && config.expiryWarningSeconds !== Number(raw.expiryWarningSeconds)) {
    errors.push('accountMonitoring.expiryWarningSeconds must be between 0 and 31536000')
  }
  return { errors, warnings, config: errors.length === 0 ? config : null }
}

export const inspectAccountConfigTrust = (configPath, { uid = process.getuid?.() } = {}) => {
  try {
    const stat = fs.lstatSync(configPath)
    if (!stat.isFile() || stat.isSymbolicLink()) return { trusted: false, reason: 'not-regular-file' }
    if (uid !== undefined && stat.uid !== uid) return { trusted: false, reason: 'wrong-owner' }
    if ((stat.mode & 0o022) !== 0) return { trusted: false, reason: 'group-or-world-writable' }
    return { trusted: true, reason: 'owned-regular-file', mode: stat.mode & 0o777, uid: stat.uid, mtimeMs: stat.mtimeMs, size: stat.size }
  } catch (error) {
    return { trusted: false, reason: error.code === 'ENOENT' ? 'missing' : 'stat-failed', error: error.message }
  }
}

export const loadAccountMonitoringConfig = ({ env = process.env, configPath = resolveGuardUserConfigPath(env) } = {}) => {
  const trust = inspectAccountConfigTrust(configPath)
  if (!trust.trusted) return { configPath, trust, rawUserConfig: {}, config: { schemaVersion: 1, enabled: false, passiveIntervalSeconds: 60, expiryWarningSeconds: 1800, monitors: [] }, errors: trust.reason === 'missing' ? [] : [`untrusted Guard user config: ${trust.reason}`], warnings: [] }
  try {
    const rawUserConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))
    if (!plainObject(rawUserConfig)) throw new Error('Guard user config must be an object')
    if (rawUserConfig.accountMonitoring === undefined) {
      return { configPath, trust, rawUserConfig, config: { schemaVersion: 1, enabled: false, passiveIntervalSeconds: 60, expiryWarningSeconds: 1800, monitors: [] }, errors: [], warnings: [] }
    }
    const validation = validateAccountMonitoringConfig(rawUserConfig.accountMonitoring)
    return { configPath, trust, rawUserConfig, ...validation }
  } catch (error) {
    return { configPath, trust, rawUserConfig: {}, config: null, errors: [error.message], warnings: [] }
  }
}

const safeChildEnv = (overrides = {}, env = process.env) => {
  const result = {}
  for (const key of SAFE_INHERITED_ENV) {
    if (env[key] !== undefined) result[key] = env[key]
  }
  if (!result.TERM) result.TERM = 'dumb'
  return { ...result, ...overrides }
}

export const buildTargetCommand = ({ target, argv, interactive = false }) => {
  if (target.type !== 'docker') return { command: argv[0], args: argv.slice(1), targetLabel: target.label || 'This Mac' }
  const args = ['exec']
  if (interactive) args.push('-it')
  if (target.user) args.push('--user', target.user)
  for (const [key, value] of Object.entries(target.environment || {})) args.push('-e', `${key}=${value}`)
  args.push(target.container, ...argv)
  return { command: target.dockerPath || '/usr/local/bin/docker', args, targetLabel: target.label || target.container }
}

const runCaptured = ({ command, args, cwd, env, timeoutMs, maxOutputBytes }) => new Promise((resolve) => {
  let child
  try {
    child = spawn(command, args, { cwd: cwd || undefined, env, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (error) {
    resolve({ exitCode: null, signal: '', stdout: '', stderr: '', errorCode: error.code || 'spawn-failed', timedOut: false, truncated: false })
    return
  }
  let stdout = Buffer.alloc(0)
  let stderr = Buffer.alloc(0)
  let capturedBytes = 0
  let truncated = false
  const collect = (current, chunk) => {
    if (capturedBytes >= maxOutputBytes) {
      truncated = true
      return current
    }
    const remaining = maxOutputBytes - capturedBytes
    if (chunk.length > remaining) truncated = true
    const accepted = chunk.subarray(0, remaining)
    capturedBytes += accepted.length
    return Buffer.concat([current, accepted])
  }
  child.stdout.on('data', (chunk) => { stdout = collect(stdout, chunk) })
  child.stderr.on('data', (chunk) => { stderr = collect(stderr, chunk) })
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    child.kill('SIGTERM')
    setTimeout(() => child.kill('SIGKILL'), 250).unref()
  }, timeoutMs)
  child.on('error', (error) => {
    clearTimeout(timer)
    resolve({ exitCode: null, signal: '', stdout: '', stderr: '', errorCode: error.code || 'spawn-failed', timedOut, truncated })
  })
  child.on('close', (exitCode, signal) => {
    clearTimeout(timer)
    resolve({ exitCode, signal: signal || '', stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8'), errorCode: '', timedOut, truncated })
  })
})

const staticPrefixForGlob = (pattern) => {
  const index = pattern.search(/[*?[\]]/)
  if (index === -1) return path.dirname(pattern)
  const prefix = pattern.slice(0, index)
  return prefix.endsWith(path.sep) ? prefix.slice(0, -1) : path.dirname(prefix)
}

const walkFiles = (root, result, max) => {
  if (result.length >= max) return
  let entries
  try { entries = fs.readdirSync(root, { withFileTypes: true }) } catch { return }
  for (const entry of entries) {
    if (result.length >= max) return
    const target = path.join(root, entry.name)
    if (entry.isDirectory()) walkFiles(target, result, max)
    else if (entry.isFile()) result.push(target)
  }
}

export const expandFilePatterns = (patterns, { env = process.env, maxMatches = DEFAULT_MAX_GLOB_MATCHES } = {}) => {
  const matches = []
  for (const rawPattern of patterns || []) {
    const pattern = path.resolve(expandHome(rawPattern, env))
    if (!/[*?[\]]/.test(pattern)) {
      try { if (fs.statSync(pattern).isFile()) matches.push(pattern) } catch {}
      continue
    }
    const candidates = []
    walkFiles(staticPrefixForGlob(pattern), candidates, maxMatches)
    const regex = new RegExp(globToRegex(pattern))
    for (const candidate of candidates) {
      if (regex.test(candidate)) matches.push(candidate)
      if (matches.length >= maxMatches) break
    }
  }
  return [...new Set(matches)].slice(0, maxMatches)
}

const parseJsonSafe = (value) => {
  try { return JSON.parse(value) } catch { return null }
}

const extractFields = ({ extract, stdout, json }) => {
  const fields = {}
  for (const [field, spec] of Object.entries(extract || {})) {
    if (spec.source === 'json') {
      const value = getPointer(json, spec.pointer)
      if (value !== undefined && value !== null && !spec.omitValues?.includes(String(value))) fields[field] = String(value)
    } else {
      const match = String(stdout || '').match(new RegExp(spec.regex, spec.flags || ''))
      if (match && match[spec.group] !== undefined) fields[field] = String(match[spec.group]).trim()
    }
  }
  return fields
}

const matchesStateRule = (rule, result, json) => {
  if (rule.exitCode !== undefined && result.exitCode !== rule.exitCode) return false
  if (rule.stdoutMatches !== undefined && !new RegExp(rule.stdoutMatches, rule.flags || '').test(result.stdout)) return false
  if (rule.pointer !== undefined) {
    const value = getPointer(json, rule.pointer)
    if (rule.exists !== undefined && (value !== undefined) !== rule.exists) return false
    if (Object.prototype.hasOwnProperty.call(rule, 'equals') && value !== rule.equals) return false
  }
  return true
}

const classifyCommandState = ({ rules, result, json }) => {
  if (result.errorCode === 'ENOENT') return { state: 'unavailable', reasonCode: 'command-not-found' }
  if (result.errorCode) return { state: 'error', reasonCode: result.errorCode }
  if (result.timedOut) return { state: 'error', reasonCode: 'probe-timeout' }
  if (result.truncated) return { state: 'error', reasonCode: 'probe-output-truncated' }
  for (const rule of rules || []) {
    if (matchesStateRule(rule, result, json)) return { state: rule.state, reasonCode: 'configured-state-rule' }
  }
  return result.exitCode === 0
    ? { state: 'signedIn', reasonCode: 'command-exit-0' }
    : { state: 'signedOut', reasonCode: `command-exit-${result.exitCode}` }
}

const runCommandProbe = async ({ probe, target, stateRules = [], extract = {}, env = process.env }) => {
  const commandSpec = buildTargetCommand({ target, argv: probe.argv })
  const targetEnvironment = target.type === 'host' ? target.environment : {}
  const result = await runCaptured({
    command: commandSpec.command,
    args: commandSpec.args,
    cwd: expandHome(probe.cwd || '', env),
    env: safeChildEnv({ ...targetEnvironment, ...probe.environment }, env),
    timeoutMs: probe.timeoutMs,
    maxOutputBytes: probe.maxOutputBytes,
  })
  const json = probe.parseJson ? parseJsonSafe(result.stdout) : null
  if (
    target.type === 'docker' &&
    result.exitCode !== 0 &&
    /(?:cannot connect|failed to connect|no such container|is not running|docker api)/i.test(`${result.stdout}\n${result.stderr}`)
  ) {
    return { state: 'unavailable', reasonCode: 'docker-target-unavailable' }
  }
  if (
    target.type === 'docker' &&
    result.exitCode !== 0 &&
    /(?:executable file not found|exec failed|stat .*no such file)/i.test(`${result.stdout}\n${result.stderr}`)
  ) {
    return { state: 'unavailable', reasonCode: 'docker-command-not-found' }
  }
  const stateResult = classifyCommandState({ rules: stateRules, result, json })
  const fields = extractFields({ extract, stdout: result.stdout, json })
  return { ...stateResult, ...fields }
}

const jsonFileMatches = (json, match) => {
  for (const [pointer, expected] of Object.entries(match || {})) {
    const value = getPointer(json, pointer)
    if (plainObject(expected) && Object.prototype.hasOwnProperty.call(expected, 'exists')) {
      if ((value !== undefined) !== Boolean(expected.exists)) return false
    } else if (value !== expected) return false
  }
  return true
}

const runJsonFilesProbe = ({ probe, extract, env = process.env }) => {
  const candidates = []
  let oversized = false
  for (const file of expandFilePatterns(probe.paths, { env })) {
    let json
    let stat
    try {
      stat = fs.statSync(file)
      if (stat.size > probe.maxOutputBytes) {
        oversized = true
        continue
      }
      json = JSON.parse(fs.readFileSync(file, 'utf8'))
    } catch { continue }
    if (!jsonFileMatches(json, probe.match)) continue
    const fields = extractFields({ extract, stdout: '', json })
    candidates.push({ fields, mtimeMs: stat.mtimeMs, expiryMs: Date.parse(fields.expiresAt || '') || 0 })
  }
  if (candidates.length === 0) {
    return oversized
      ? { state: 'error', reasonCode: 'credential-cache-too-large' }
      : { state: 'signedOut', reasonCode: 'matching-credential-cache-missing' }
  }
  candidates.sort((left, right) => probe.choose === 'latestMtime'
    ? right.mtimeMs - left.mtimeMs
    : right.expiryMs - left.expiryMs)
  const selected = candidates[0]
  const expiresAt = isoTimestamp(selected.fields.expiresAt)
  return {
    state: expiresAt && Date.parse(expiresAt) <= Date.now() ? 'expired' : 'signedIn',
    reasonCode: expiresAt ? 'credential-cache-expiry' : 'credential-cache-present',
    ...selected.fields,
    expiresAt,
  }
}

const runLatestMtimeProbe = ({ probe, env = process.env }) => {
  let latest = 0
  for (const file of expandFilePatterns(probe.paths, { env })) {
    try { latest = Math.max(latest, fs.statSync(file).mtimeMs) } catch {}
  }
  return latest > 0
    ? { timestamp: new Date(latest).toISOString(), sourceLabel: probe.sourceLabel }
    : { timestamp: '', sourceLabel: probe.sourceLabel }
}

const wildcard = (value, pattern) => {
  if (typeof pattern !== 'string') return value === pattern
  return new RegExp(globToRegex(pattern), 'i').test(String(value ?? ''))
}

const eventMatches = (event, match) => Object.entries(match || {}).every(([field, expected]) => {
  const value = dottedValue(event, field)
  return Array.isArray(expected) ? expected.some((entry) => wildcard(value, entry)) : wildcard(value, expected)
})

const runGuardEventsProbe = ({ probe, events = [] }) => {
  let latest = ''
  for (const event of events) {
    if (!eventMatches(event, probe.match)) continue
    for (const field of probe.timestampFields) {
      const candidate = isoTimestamp(dottedValue(event, field))
      if (candidate && (!latest || candidate > latest)) latest = candidate
    }
  }
  return { timestamp: latest, sourceLabel: probe.sourceLabel }
}

const runStatusProbe = async ({ monitor, env, events }) => {
  const { probe, stateRules, extract } = monitor.status
  if (probe.type === 'command') return runCommandProbe({ probe, target: monitor.target, stateRules, extract, env })
  if (monitor.target.type === 'docker') return { state: 'error', reasonCode: 'docker-file-probe-unsupported' }
  if (probe.type === 'jsonFiles') return runJsonFilesProbe({ probe, extract, env })
  if (probe.type === 'latestMtime') {
    const result = runLatestMtimeProbe({ probe, env })
    return { state: result.timestamp ? 'signedIn' : 'signedOut', reasonCode: result.timestamp ? 'local-file-present' : 'local-file-missing' }
  }
  const result = runGuardEventsProbe({ probe, events })
  return { state: result.timestamp ? 'signedIn' : 'unknown', reasonCode: result.timestamp ? 'matching-event-observed' : 'no-matching-event' }
}

const runActivityProbe = async ({ probe, monitor, env, events }) => {
  if (probe.type === 'latestMtime') return runLatestMtimeProbe({ probe, env })
  if (probe.type === 'guardEvents') return runGuardEventsProbe({ probe, events })
  if (probe.type === 'command') {
    const result = await runCommandProbe({
      probe,
      target: monitor.target,
      stateRules: [],
      extract: { lastUsedAt: { source: 'json', pointer: '/lastUsedAt' } },
      env,
    })
    return { timestamp: isoTimestamp(result.lastUsedAt), sourceLabel: probe.label || 'configured activity probe' }
  }
  const result = runJsonFilesProbe({ probe, extract: { lastUsedAt: { source: 'json', pointer: '/lastUsedAt' } }, env })
  return { timestamp: isoTimestamp(result.lastUsedAt), sourceLabel: probe.sourceLabel }
}

export const emptyAccountSnapshot = (monitor, checkedAt = '') => ({
  schemaVersion: ACCOUNT_SNAPSHOT_VERSION,
  id: monitor.id,
  label: monitor.label,
  providerLabel: monitor.providerLabel,
  target: { type: monitor.target.type, label: monitor.target.label },
  state: 'unknown',
  identity: '',
  lastUsedAt: '',
  lastUsedSource: '',
  expiresAt: '',
  checkedAt,
  stale: true,
  reasonCode: 'not-checked',
  loginAvailable: Boolean(monitor.login),
  expiryWarningSeconds: monitor.expiryWarningSeconds,
})

export const runAccountMonitor = async ({ monitor, previous = null, mode = 'passive', env = process.env, events = [], now = new Date() }) => {
  const checkedAt = now.toISOString()
  let statusResult
  if (monitor.status.cadence === 'manual' && mode !== 'manual') {
    statusResult = previous
      ? { state: previous.state, identity: previous.identity, expiresAt: previous.expiresAt, reasonCode: 'manual-probe-not-run' }
      : { state: 'unknown', reasonCode: 'manual-probe-not-run' }
  } else {
    statusResult = await runStatusProbe({ monitor, env, events })
  }
  const activityResults = await Promise.all(monitor.activity.map((probe) => runActivityProbe({ probe, monitor, env, events })))
  if (statusResult.lastUsedAt) {
    activityResults.push({
      timestamp: isoTimestamp(statusResult.lastUsedAt),
      sourceLabel: monitor.status.activitySourceLabel || 'status metadata',
    })
  }
  const latestActivity = activityResults
    .filter((entry) => entry.timestamp)
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp))[0] || null
  const expiresAt = isoTimestamp(statusResult.expiresAt || previous?.expiresAt)
  let state = ACCOUNT_STATES.has(statusResult.state) ? statusResult.state : 'unknown'
  if (expiresAt && Date.parse(expiresAt) <= now.getTime()) state = 'expired'
  const usingCachedManualStatus = monitor.status.cadence === 'manual' && mode !== 'manual'
  const cachedCheckedMs = Date.parse(previous?.checkedAt || '')
  const cachedStatusIsStale = !Number.isFinite(cachedCheckedMs) || now.getTime() - cachedCheckedMs > (monitor.staleAfterSeconds || 120) * 1000
  return {
    schemaVersion: ACCOUNT_SNAPSHOT_VERSION,
    id: monitor.id,
    label: monitor.label,
    providerLabel: monitor.providerLabel,
    target: { type: monitor.target.type, label: monitor.target.label },
    state,
    identity: String(statusResult.identity || previous?.identity || ''),
    lastUsedAt: latestActivity?.timestamp || previous?.lastUsedAt || '',
    lastUsedSource: latestActivity?.sourceLabel || previous?.lastUsedSource || '',
    expiresAt,
    checkedAt: usingCachedManualStatus && previous?.checkedAt ? previous.checkedAt : checkedAt,
    stale: usingCachedManualStatus ? cachedStatusIsStale : false,
    reasonCode: String(statusResult.reasonCode || 'unknown'),
    loginAvailable: Boolean(monitor.login),
    expiryWarningSeconds: monitor.expiryWarningSeconds,
  }
}

export const buildDefaultAccountMonitoringConfig = ({
  home = os.homedir(),
  awsStartUrl = '',
  packetsafariWebsiteDir = path.join(home, 'code', 'packetsafari-website'),
} = {}) => ({
  schemaVersion: ACCOUNT_MONITORING_VERSION,
  passiveIntervalSeconds: DEFAULT_PASSIVE_INTERVAL_SECONDS,
  expiryWarningSeconds: DEFAULT_EXPIRY_WARNING_SECONDS,
  monitors: [
    {
      id: 'aws-sso',
      label: 'AWS SSO — default/admin',
      providerLabel: 'AWS',
      target: { type: 'host', label: 'This Mac' },
      status: {
        cadence: 'passive',
        probe: {
          type: 'jsonFiles',
          paths: [path.join(home, '.aws', 'sso', 'cache', '*.json')],
          choose: 'latestExpiry',
          match: awsStartUrl ? { '/startUrl': awsStartUrl } : { '/startUrl': { exists: true } },
        },
        extract: { expiresAt: { source: 'json', pointer: '/expiresAt' } },
      },
      activity: [{
        type: 'latestMtime',
        paths: [path.join(home, '.aws', 'cli', 'cache', '*.json')],
        sourceLabel: 'AWS CLI credential cache',
      }],
      login: {
        presentation: 'terminal',
        argv: ['/usr/local/bin/aws', 'sso', 'login', '--profile', 'default'],
      },
    },
    {
      id: 'codex-mac',
      label: 'Codex — Mac',
      providerLabel: 'OpenAI',
      target: { type: 'host', label: 'This Mac' },
      status: {
        cadence: 'passive',
        probe: {
          type: 'command',
          argv: ['/Applications/ChatGPT.app/Contents/Resources/codex', 'login', 'status'],
        },
        stateRules: [
          { exitCode: 0, stdoutMatches: 'Logged in', state: 'signedIn' },
          { exitCode: 0, state: 'signedIn' },
          { state: 'signedOut' },
        ],
        extract: {
          identity: { source: 'stdout', regex: 'Logged in(?: using| as)?\\s+(.+)$', flags: 'im', group: 1 },
        },
      },
      activity: [{
        type: 'latestMtime',
        paths: [path.join(home, '.codex', 'sessions', '**', '*.jsonl')],
        sourceLabel: 'Codex session files',
      }],
      login: {
        presentation: 'terminal',
        argv: ['/Applications/ChatGPT.app/Contents/Resources/codex', 'login', '--device-auth'],
      },
    },
    {
      id: 'codex-packetsafari-worker',
      label: 'Codex — PacketSafari worker',
      providerLabel: 'OpenAI',
      target: {
        type: 'docker',
        label: 'PacketSafari worker',
        dockerPath: '/usr/local/bin/docker',
        container: 'worker',
        user: '4242:4141',
        environment: { CODEX_HOME: '/var/lib/packetsafari/codex' },
      },
      status: {
        cadence: 'passive',
        probe: { type: 'command', argv: ['/usr/local/bin/codex', 'login', 'status'] },
        stateRules: [
          { exitCode: 0, stdoutMatches: 'Logged in', state: 'signedIn' },
          { exitCode: 0, state: 'signedIn' },
          { state: 'signedOut' },
        ],
        extract: {
          identity: { source: 'stdout', regex: 'Logged in(?: using| as)?\\s+(.+)$', flags: 'im', group: 1 },
        },
      },
      activity: [{
        type: 'command',
        label: 'PacketSafari Codex session files',
        parseJson: true,
        argv: [
          '/bin/sh',
          '-lc',
          "latest=$(find /var/lib/packetsafari/codex/sessions -type f -name '*.jsonl' -printf '%T@\\n' 2>/dev/null | sort -nr | head -1); if [ -n \"$latest\" ]; then date -u -d \"@${latest%.*}\" '+{\"lastUsedAt\":\"%Y-%m-%dT%H:%M:%SZ\"}'; else printf '{\"lastUsedAt\":\"\"}\\n'; fi",
        ],
      }],
      login: {
        presentation: 'terminal',
        argv: ['/usr/local/bin/codex', 'login', '--device-auth'],
      },
    },
    {
      id: 'cloudflare-wrangler',
      label: 'Cloudflare Wrangler',
      providerLabel: 'Cloudflare',
      target: { type: 'host', label: 'PacketSafari website' },
      status: {
        cadence: 'manual',
        probe: {
          type: 'command',
          argv: [path.join(packetsafariWebsiteDir, 'node_modules', '.bin', 'wrangler'), 'whoami', '--json'],
          cwd: packetsafariWebsiteDir,
          environment: { PATH: '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', CI: 'true' },
          parseJson: true,
        },
        stateRules: [
          { exitCode: 0, state: 'signedIn' },
          { state: 'signedOut' },
        ],
      },
      activity: [{
        type: 'guardEvents',
        match: { command: '*wrangler*' },
        timestampFields: ['at', 'timestamp', 'time'],
        sourceLabel: 'Guard-observed Wrangler command',
      }],
      login: {
        presentation: 'terminal',
        cwd: packetsafariWebsiteDir,
        environment: { PATH: '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin' },
        argv: [path.join(packetsafariWebsiteDir, 'node_modules', '.bin', 'wrangler'), 'login', '--device', '--use-keyring'],
      },
    },
    {
      id: 'tailscale',
      label: 'Tailscale',
      providerLabel: 'Tailscale',
      target: { type: 'host', label: 'This Mac' },
      status: {
        cadence: 'passive',
        activitySourceLabel: 'Local tailnet activity',
        probe: {
          type: 'command',
          argv: ['/Applications/Tailscale.app/Contents/MacOS/Tailscale', 'status', '--json'],
          parseJson: true,
        },
        stateRules: [
          { pointer: '/BackendState', equals: 'Running', state: 'signedIn' },
          { pointer: '/BackendState', equals: 'NeedsLogin', state: 'signedOut' },
          { state: 'unavailable' },
        ],
        extract: {
          identity: { source: 'json', pointer: '/CurrentTailnet/Name' },
          expiresAt: {
            source: 'json',
            pointer: '/Self/KeyExpiry',
            omitValues: ['0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000Z'],
          },
          lastUsedAt: {
            source: 'json',
            pointer: '/Self/LastWrite',
            omitValues: ['0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000Z'],
          },
        },
      },
      activity: [],
      login: {
        presentation: 'terminal',
        argv: ['/Applications/Tailscale.app/Contents/MacOS/Tailscale', 'login'],
      },
    },
  ],
})

const writeJsonPrivate = (target, value) => {
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 })
  const temporary = `${target}.${process.pid}.tmp`
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
  fs.chmodSync(temporary, 0o600)
  fs.renameSync(temporary, target)
}

export const readAccountSnapshots = (statePath) => {
  try {
    const value = JSON.parse(fs.readFileSync(statePath, 'utf8'))
    return plainObject(value?.snapshots) ? value.snapshots : {}
  } catch { return {} }
}

export const writeAccountSnapshots = (statePath, snapshots) => writeJsonPrivate(statePath, {
  schemaVersion: ACCOUNT_SNAPSHOT_VERSION,
  updatedAt: new Date().toISOString(),
  snapshots,
})

const transitionFields = ['state', 'identity', 'expiresAt']
export const accountSnapshotChanged = (before, after) => !before || transitionFields.some((field) => before[field] !== after[field])

export const loginPreview = (monitor) => {
  if (!monitor.login) return null
  const command = buildTargetCommand({ target: monitor.target, argv: monitor.login.argv, interactive: monitor.login.presentation === 'terminal' })
  const previewArgs = command.args.map((argument, index, argumentsList) => {
    if (argumentsList[index - 1] !== '-e') return argument
    const separator = argument.indexOf('=')
    return separator === -1 ? argument : `${argument.slice(0, separator)}=<redacted>`
  })
  return {
    id: monitor.id,
    label: monitor.label,
    providerLabel: monitor.providerLabel,
    target: { type: monitor.target.type, label: monitor.target.label },
    presentation: monitor.login.presentation,
    argv: [command.command, ...previewArgs],
    cwd: monitor.login.cwd || '',
    environmentKeys: [...new Set([...Object.keys(monitor.target.environment || {}), ...Object.keys(monitor.login.environment || {})])].sort(),
  }
}

export const runAccountLogin = async ({ monitor, env = process.env, onEvent = () => {} }) => {
  if (!monitor.login) throw new Error(`account monitor has no login action: ${monitor.id}`)
  const commandSpec = buildTargetCommand({ target: monitor.target, argv: monitor.login.argv, interactive: true })
  const targetEnvironment = monitor.target.type === 'host' ? monitor.target.environment : {}
  onEvent({ type: 'account.login.started', accountId: monitor.id, label: monitor.label, target: monitor.target.label })
  const exitCode = await new Promise((resolve, reject) => {
    const child = spawn(commandSpec.command, commandSpec.args, {
      cwd: expandHome(monitor.login.cwd || '', env) || undefined,
      env: safeChildEnv({ ...targetEnvironment, ...monitor.login.environment }, env),
      stdio: 'inherit',
    })
    child.on('error', reject)
    child.on('close', (code) => resolve(code ?? 1))
  })
  onEvent({
    type: exitCode === 0 ? 'account.login.completed' : 'account.login.failed',
    accountId: monitor.id,
    label: monitor.label,
    target: monitor.target.label,
    exitCode,
  })
  return exitCode
}

export class AccountMonitorStore {
  constructor({ stateDir, eventLogPath = '', env = process.env, getEvents = () => [], onEvent = () => {} }) {
    this.stateDir = stateDir
    this.statePath = resolveAccountStatePath(stateDir)
    this.eventLogPath = eventLogPath
    this.env = env
    this.getEvents = getEvents
    this.onEvent = onEvent
    this.snapshots = readAccountSnapshots(this.statePath)
    this.loaded = null
  }

  reloadConfig() {
    this.loaded = loadAccountMonitoringConfig({ env: this.env })
    return this.loaded
  }

  config() {
    return this.reloadConfig()
  }

  list() {
    const loaded = this.config()
    if (!loaded.config) return { ...loaded, accounts: [] }
    const now = Date.now()
    const accounts = loaded.config.monitors.filter((monitor) => monitor.enabled).map((monitor) => {
      const snapshot = this.snapshots[monitor.id] || emptyAccountSnapshot(monitor)
      const checkedMs = Date.parse(snapshot.checkedAt || '')
      const stale = !Number.isFinite(checkedMs) || now - checkedMs > monitor.staleAfterSeconds * 1000
      const expiresMs = Date.parse(snapshot.expiresAt || '')
      return {
        ...snapshot,
        state: Number.isFinite(expiresMs) && expiresMs <= now ? 'expired' : snapshot.state,
        stale,
        expiryWarningSeconds: monitor.expiryWarningSeconds,
      }
    })
    return { configPath: loaded.configPath, errors: loaded.errors, warnings: loaded.warnings, accounts }
  }

  monitor(id) {
    const loaded = this.config()
    if (!loaded.config) return { loaded, monitor: null }
    return { loaded, monitor: loaded.config.monitors.find((entry) => entry.enabled && entry.id === id) || null }
  }

  appendEvent(event) {
    if (!this.eventLogPath) return
    fs.mkdirSync(path.dirname(this.eventLogPath), { recursive: true, mode: 0o700 })
    const normalized = { schemaVersion: 1, at: new Date().toISOString(), ...event }
    fs.appendFileSync(this.eventLogPath, `${JSON.stringify(normalized)}\n`)
    this.onEvent(normalized)
  }

  async refresh({ id = '', mode = 'manual' } = {}) {
    const loaded = this.config()
    if (!loaded.config) throw new Error(loaded.errors.join('; ') || 'invalid account monitoring config')
    const monitors = loaded.config.monitors.filter((monitor) => monitor.enabled && (!id || monitor.id === id))
    if (id && monitors.length === 0) throw new Error(`account monitor not found: ${id}`)
    const events = this.getEvents() || []
    const queue = [...monitors]
    const results = []
    const workers = Array.from({ length: Math.min(4, queue.length) }, async () => {
      while (queue.length > 0) {
        const monitor = queue.shift()
        const before = this.snapshots[monitor.id] || null
        let after
        try {
          after = await runAccountMonitor({ monitor, previous: before, mode, env: this.env, events })
        } catch (error) {
          after = {
            ...emptyAccountSnapshot(monitor, new Date().toISOString()),
            state: error.code === 'ENOENT' ? 'unavailable' : 'error',
            stale: false,
            reasonCode: error.code || 'probe-failed',
          }
        }
        this.snapshots[monitor.id] = after
        results.push(after)
        if (accountSnapshotChanged(before, after)) {
          this.appendEvent({ type: 'account.session.changed', accountId: monitor.id, beforeState: before?.state || '', snapshot: after })
        }
      }
    })
    await Promise.all(workers)
    writeAccountSnapshots(this.statePath, this.snapshots)
    return results.sort((left, right) => left.label.localeCompare(right.label))
  }

  preview(id) {
    const { loaded, monitor } = this.monitor(id)
    if (!loaded.config) throw new Error(loaded.errors.join('; ') || 'invalid account monitoring config')
    if (!monitor) throw new Error(`account monitor not found: ${id}`)
    return loginPreview(monitor)
  }
}
