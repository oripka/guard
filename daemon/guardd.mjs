#!/usr/bin/env node
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { URL } from 'node:url'

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 8765
const DEFAULT_MAX_EVENTS = 500
const DEFAULT_POLL_MS = 1000
const DEFAULT_REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

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

const resolveGuardPolicyRoot = (env = process.env) => {
  if (env.GUARDD_POLICY_ROOT) return path.resolve(expandHome(env.GUARDD_POLICY_ROOT))
  if (env.GUARD_PROJECT_DIR) return path.resolve(expandHome(env.GUARD_PROJECT_DIR))
  return process.cwd()
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
  const config = {
    host: env.GUARDD_HOST || DEFAULT_HOST,
    port: parsePort(env.GUARDD_PORT, DEFAULT_PORT),
    eventLogPath: resolveGuardEventLogPath(env),
    maxEvents: parsePositiveInt(env.GUARDD_MAX_EVENTS, DEFAULT_MAX_EVENTS),
    pollMs: parsePositiveInt(env.GUARDD_POLL_MS, DEFAULT_POLL_MS),
    policyRoot: resolveGuardPolicyRoot(env),
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
  --policy-root PATH   Project root containing .guard/*.json (default: cwd or GUARDD_POLICY_ROOT)
  --repo-root PATH     Guard repo root for built-in profiles/templates (default: ${DEFAULT_REPO_ROOT})
  --api-token TOKEN    Require a Bearer or X-Guard-Token token for the HTTP API
  -h, --help           Show this help

Endpoints:
  GET /health
  GET /events?limit=N&type=network.decision
  GET /policy?profile=guard
  GET /profiles
  GET /profiles/:name
  GET /templates
  GET /templates/:name
  GET /templates/:name/preview?profile=guard
  POST /profiles/:name/rules
  POST /profiles/:name/tls
  POST /templates/:name/preview
  POST /templates/:name/apply
`

class EventTail {
  constructor({ eventLogPath, maxEvents, pollMs }) {
    this.eventLogPath = eventLogPath
    this.maxEvents = maxEvents
    this.pollMs = pollMs
    this.events = []
    this.offset = 0
    this.partial = ''
    this.timer = null
    this.readError = null
    this.invalidLineCount = 0
    this.lastReadAt = null
  }

  start() {
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
      return
    }

    if (!stat.isFile()) {
      this.readError = 'event log path is not a file'
      return
    }

    if (stat.size < this.offset) {
      this.offset = 0
      this.partial = ''
    }
    if (stat.size === this.offset) return

    const length = stat.size - this.offset
    const fd = fs.openSync(this.eventLogPath, 'r')
    try {
      const buffer = Buffer.alloc(length)
      fs.readSync(fd, buffer, 0, length, this.offset)
      this.offset = stat.size
      this.consume(buffer.toString('utf8'))
      this.readError = null
      this.lastReadAt = new Date().toISOString()
    } catch (error) {
      this.readError = error.message
    } finally {
      fs.closeSync(fd)
    }
  }

  consume(chunk) {
    const lines = `${this.partial}${chunk}`.split(/\r?\n/)
    this.partial = lines.pop() || ''
    for (const line of lines) {
      if (!line.trim()) continue
      try {
        this.push(JSON.parse(line))
      } catch {
        this.invalidLineCount += 1
      }
    }
  }

  push(event) {
    this.events.push(event)
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents)
    }
  }

  recent({ limit, type }) {
    let events = this.events
    if (type) events = events.filter((event) => event?.type === type)
    return events.slice(-limit).reverse()
  }
}

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

const mergeUniqueArray = (left = [], right = []) => {
  const values = []
  for (const value of [...left, ...right]) {
    if (!values.includes(value)) values.push(value)
  }
  return values
}

const mergeProfileConfig = (base = {}, overlay = {}) => {
  const merged = structuredClone(base)
  for (const [key, value] of Object.entries(overlay)) {
    if (key === 'imports') continue
    const current = merged[key]
    if (Array.isArray(current) || Array.isArray(value)) {
      merged[key] = mergeUniqueArray(
        Array.isArray(current) ? current : [],
        Array.isArray(value) ? value : [],
      )
    } else if (isPlainObject(current) && isPlainObject(value)) {
      merged[key] = mergeProfileConfig(current, value)
    } else {
      merged[key] = structuredClone(value)
    }
  }
  return merged
}

const resolveProfileImportPath = ({ repoRoot, configPath, ref }) => {
  if (typeof ref !== 'string' || !ref.trim()) {
    throw new Error(`invalid profile import in ${configPath}`)
  }

  const value = ref.trim()
  if (path.isAbsolute(value) || value.startsWith('.') || value.includes('/')) {
    return path.resolve(path.dirname(configPath), value)
  }
  return path.resolve(repoRoot, 'templates', 'imports', `${value}.json`)
}

const loadProfileConfig = ({ repoRoot, configPath, seen = new Set() }) => {
  const normalized = path.resolve(configPath)
  if (seen.has(normalized)) throw new Error(`profile import cycle detected at ${normalized}`)
  seen.add(normalized)

  const cfg = JSON.parse(fs.readFileSync(normalized, 'utf8'))
  const imports = Array.isArray(cfg.imports) ? cfg.imports : []
  let merged = {}
  for (const ref of imports) {
    const importPath = resolveProfileImportPath({ repoRoot, configPath: normalized, ref })
    if (!fs.existsSync(importPath)) {
      throw new Error(`unknown profile import "${ref}" from ${normalized}`)
    }
    merged = mergeProfileConfig(
      merged,
      loadProfileConfig({ repoRoot, configPath: importPath, seen }),
    )
  }

  seen.delete(normalized)
  return mergeProfileConfig(merged, cfg)
}

const readJsonFile = (filePath) => JSON.parse(fs.readFileSync(filePath, 'utf8'))
const writeJsonFile = (filePath, value) => {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`)
}

const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

const ruleHash = (value) => crypto.createHash('sha256').update(stableJson(value)).digest('hex')
const ruleMetadataKey = (field, value) => `${field}:${ruleHash(value).slice(0, 16)}`
const profileVersion = (config) => `sha256:${ruleHash(config)}`
const profileVersionInfo = (config) => {
  const hash = ruleHash(config)
  return {
    version: `sha256:${hash}`,
    hash: `sha256:${hash}`,
    shortHash: hash.slice(0, 16),
  }
}

const appendJsonLine = (target, value) => {
  try {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.appendFileSync(target, `${JSON.stringify(value)}\n`)
  } catch {}
}

const isSafeName = (name) => /^[A-Za-z0-9._-]+$/.test(name)
const MUTABLE_ARRAY_FIELDS = new Set([
  'network.allowedDomains',
  'network.deniedDomains',
  'filesystem.allowRead',
  'filesystem.denyRead',
  'filesystem.allowWrite',
  'filesystem.denyWrite',
])

const normalizeHttpRule = (rule = {}) => {
  const host = typeof rule.host === 'string' ? rule.host.trim().toLowerCase() : ''
  const cidr = typeof rule.cidr === 'string' ? rule.cidr.trim() : ''
  if ((!host && !cidr) || (host && cidr)) {
    throw new Error('HTTP rules require exactly one of host or cidr')
  }
  const normalized = host ? { host } : { cidr }
  const methods = Array.isArray(rule.methods)
    ? rule.methods.map((value) => String(value).trim().toUpperCase()).filter(Boolean)
    : []
  const paths = Array.isArray(rule.paths)
    ? rule.paths.map((value) => String(value).trim()).filter(Boolean)
    : []
  if (methods.length > 0) normalized.methods = [...new Set(methods)]
  if (paths.length > 0) normalized.paths = [...new Set(paths)]
  return normalized
}

const ensurePathArray = (cfg, field, create) => {
  const [section, key] = field.split('.')
  if (!cfg[section]) {
    if (!create) return null
    cfg[section] = {}
  }
  if (!Array.isArray(cfg[section][key])) {
    if (!create) return null
    cfg[section][key] = []
  }
  return cfg[section][key]
}

const ensureRuleMetadata = (cfg, field, value, source = 'guardd') => {
  if (!cfg.ruleMetadata || typeof cfg.ruleMetadata !== 'object' || Array.isArray(cfg.ruleMetadata)) {
    cfg.ruleMetadata = {}
  }
  const hash = ruleHash(value)
  const key = `${field}:${hash.slice(0, 16)}`
  const existing = cfg.ruleMetadata[key] || {}
  const now = new Date().toISOString()
  cfg.ruleMetadata[key] = {
    ...existing,
    id: `rule_${hash.slice(0, 16)}`,
    field,
    value: structuredClone(value),
    valueHash: `sha256:${hash}`,
    createdAt: existing.createdAt || now,
    updatedAt: now,
    source: existing.source || source,
    disabled: existing.disabled === true,
  }
  return { metadataKey: key, ruleId: cfg.ruleMetadata[key].id }
}

const setRuleMetadataDisabled = (cfg, field, value, disabled, source = 'guardd') => {
  const metadata = ensureRuleMetadata(cfg, field, value, source)
  const wasDisabled = cfg.ruleMetadata[metadata.metadataKey].disabled === true
  cfg.ruleMetadata[metadata.metadataKey].disabled = Boolean(disabled)
  cfg.ruleMetadata[metadata.metadataKey].updatedAt = new Date().toISOString()
  return { ...metadata, metadataChanged: wasDisabled !== Boolean(disabled) }
}

const removeRuleMetadata = (cfg, field, value) => {
  const key = ruleMetadataKey(field, value)
  if (cfg.ruleMetadata && typeof cfg.ruleMetadata === 'object' && !Array.isArray(cfg.ruleMetadata)) {
    delete cfg.ruleMetadata[key]
  }
  return { metadataKey: key, ruleId: `rule_${key.split(':')[1]}` }
}

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
    if (!MUTABLE_ARRAY_FIELDS.has(field)) throw new Error(`unsupported profile field: ${field}`)
    const profilePath = this.resolveProjectProfilePath(profile)
    if (!profilePath) throw new Error(`project profile not found: ${profile}`)
    const cfg = readJsonFile(profilePath)
    const beforeVersion = profileVersion(cfg)
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion, profile })
    const values = ensurePathArray(cfg, field, action === 'add' || action === 'enable')
    const before = values ? [...values] : []
    let changed = false

    if (action === 'add' || action === 'enable') {
      if (disabled === true) {
        const next = values.filter((entry) => entry !== value)
        changed = next.length !== values.length
        if (changed) values.splice(0, values.length, ...next)
      } else if (!values.includes(value)) {
        values.push(value)
        changed = true
      }
      const { metadataChanged, ...metadata } = setRuleMetadataDisabled(cfg, field, String(value), disabled === true)
      changed = changed || metadataChanged
      if (changed) writeJsonFile(profilePath, cfg)
      return {
        action,
        changed,
        profile,
        path: profilePath,
        field,
        value,
        disabled: disabled === true,
        beforeVersion,
        ...profileVersionInfo(cfg),
        ...metadata,
        before,
        after: ensurePathArray(cfg, field, false) || [],
      }
    } else if (values) {
      const next = values.filter((entry) => entry !== value)
      changed = next.length !== values.length
      if (changed) values.splice(0, values.length, ...next)
      if (action === 'disable' || action === 'remove') {
        const metadata = action === 'disable'
          ? setRuleMetadataDisabled(cfg, field, String(value), true)
          : removeRuleMetadata(cfg, field, String(value))
        const { metadataChanged = false, ...publicMetadata } = metadata
        changed = changed || action === 'disable' || metadataChanged
        if (changed) writeJsonFile(profilePath, cfg)
        return {
          action,
          changed,
          profile,
          path: profilePath,
          field,
          value,
          disabled: action === 'disable',
          beforeVersion,
          ...profileVersionInfo(cfg),
          ...publicMetadata,
          before,
          after: ensurePathArray(cfg, field, false) || [],
        }
      }
    } else if (action === 'disable') {
      const { metadataChanged: _metadataChanged, ...metadata } = setRuleMetadataDisabled(cfg, field, String(value), true)
      writeJsonFile(profilePath, cfg)
      return {
        action,
        changed: true,
        profile,
        path: profilePath,
        field,
        value,
        disabled: true,
        beforeVersion,
        ...profileVersionInfo(cfg),
        ...metadata,
        before,
        after: ensurePathArray(cfg, field, false) || [],
      }
    } else if (action !== 'remove') {
      throw new Error(`unsupported rule action: ${action}`)
    }

    const metadata = changed
      ? action === 'add'
        ? ensureRuleMetadata(cfg, field, String(value))
        : removeRuleMetadata(cfg, field, String(value))
      : {
          metadataKey: ruleMetadataKey(field, String(value)),
          ruleId: `rule_${ruleMetadataKey(field, String(value)).split(':')[1]}`,
        }
    if (changed) writeJsonFile(profilePath, cfg)
    return {
      action,
      changed,
      profile,
      path: profilePath,
      field,
      value,
      disabled: false,
      beforeVersion,
      ...profileVersionInfo(cfg),
      ...metadata,
      before,
      after: ensurePathArray(cfg, field, false) || [],
    }
  }

  mutateHttpRule({ profile, rule, action, ifMatch, disabled = false }) {
    const profilePath = this.resolveProjectProfilePath(profile)
    if (!profilePath) throw new Error(`project profile not found: ${profile}`)
    const cfg = readJsonFile(profilePath)
    const beforeVersion = profileVersion(cfg)
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion, profile })
    if (!cfg.network) cfg.network = {}
    if (!Array.isArray(cfg.network.httpRules)) cfg.network.httpRules = []
    const normalized = normalizeHttpRule(rule)
    const key = stableJson(normalized)
    const before = [...cfg.network.httpRules]
    const index = cfg.network.httpRules.findIndex((entry) => stableJson(normalizeHttpRule(entry)) === key)
    let changed = false

    if (action === 'add' || action === 'enable') {
      if (disabled === true) {
        if (index !== -1) {
          cfg.network.httpRules.splice(index, 1)
          changed = true
        }
      } else if (index === -1) {
        cfg.network.httpRules.push(normalized)
        changed = true
      }
      const { metadataChanged, ...metadata } = setRuleMetadataDisabled(cfg, 'network.httpRules', normalized, disabled === true)
      changed = changed || metadataChanged
      if (changed) writeJsonFile(profilePath, cfg)
      return {
        action,
        changed,
        profile,
        path: profilePath,
        field: 'network.httpRules',
        value: normalized,
        disabled: disabled === true,
        beforeVersion,
        ...profileVersionInfo(cfg),
        ...metadata,
        before,
        after: cfg.network.httpRules,
      }
    } else if (action === 'remove') {
      if (index !== -1) {
        cfg.network.httpRules.splice(index, 1)
        changed = true
      }
    } else if (action === 'disable') {
      if (index !== -1) {
        cfg.network.httpRules.splice(index, 1)
        changed = true
      }
      const { metadataChanged: _metadataChanged, ...metadata } = setRuleMetadataDisabled(cfg, 'network.httpRules', normalized, true)
      changed = true
      if (changed) writeJsonFile(profilePath, cfg)
      return {
        action,
        changed,
        profile,
        path: profilePath,
        field: 'network.httpRules',
        value: normalized,
        disabled: true,
        beforeVersion,
        ...profileVersionInfo(cfg),
        ...metadata,
        before,
        after: cfg.network.httpRules,
      }
    } else {
      throw new Error(`unsupported rule action: ${action}`)
    }

    const metadata = changed
      ? action === 'add'
        ? ensureRuleMetadata(cfg, 'network.httpRules', normalized)
        : removeRuleMetadata(cfg, 'network.httpRules', normalized)
      : {
          metadataKey: ruleMetadataKey('network.httpRules', normalized),
          ruleId: `rule_${ruleMetadataKey('network.httpRules', normalized).split(':')[1]}`,
        }
    if (changed) writeJsonFile(profilePath, cfg)
    return {
      action,
      changed,
      profile,
      path: profilePath,
      field: 'network.httpRules',
      value: normalized,
      disabled: false,
      beforeVersion,
      ...profileVersionInfo(cfg),
      ...metadata,
      before,
      after: cfg.network.httpRules,
    }
  }

  mutateTls({ profile, enabled, ifMatch }) {
    const profilePath = this.resolveProjectProfilePath(profile)
    if (!profilePath) throw new Error(`project profile not found: ${profile}`)
    const cfg = readJsonFile(profilePath)
    const beforeVersion = profileVersion(cfg)
    assertVersionMatch({ expected: ifMatch, actual: beforeVersion, profile })
    if (!cfg.network) cfg.network = {}
    const before = cfg.network.tlsInspection || {}
    const next = {
      ...(before && typeof before === 'object' && !Array.isArray(before) ? before : {}),
      enabled: Boolean(enabled),
      mode: enabled ? 'ephemeral-run-ca' : 'off',
      caScope: enabled ? 'guarded-process-env' : 'none',
      userApprovalRequired: true,
    }
    const changed = stableJson(before) !== stableJson(next)
    cfg.network.tlsInspection = next
    if (changed) writeJsonFile(profilePath, cfg)
    return {
      action: enabled ? 'enable' : 'disable',
      changed,
      profile,
      path: profilePath,
      beforeVersion,
      ...profileVersionInfo(cfg),
      before,
      after: next,
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
  host === '127.0.0.1' || host === '::1' || host === 'localhost'

const extractToken = (request) => {
  const authorization = request.headers.authorization || ''
  if (authorization.startsWith('Bearer ')) return authorization.slice('Bearer '.length)
  const headerToken = request.headers['x-guard-token']
  return Array.isArray(headerToken) ? headerToken[0] : headerToken || ''
}

const isAuthorized = (request, apiToken) => !apiToken || extractToken(request) === apiToken

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

const createServer = ({ tail, policyStore, startedAt, apiToken, eventLogPath }) =>
  http.createServer(async (request, response) => {
    const url = new URL(request.url || '/', 'http://guardd.local')

    if (!isAuthorized(request, apiToken)) {
      response.setHeader('www-authenticate', 'Bearer realm="guardd"')
      writeJson(response, 401, { error: 'unauthorized' })
      return
    }

    const isMutation = request.method !== 'GET'
    if (isMutation && !apiToken) {
      writeJson(response, 403, { error: 'api_token_required' })
      return
    }

    if (!['GET', 'POST'].includes(request.method)) {
      writeJson(response, 405, { error: 'method_not_allowed' })
      return
    }

    if (request.method === 'POST') {
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
      writeJson(response, 200, {
        ok: true,
        service: 'guardd',
        startedAt,
        eventLogPath: tail.eventLogPath,
        policyRoot: policyStore.policyRoot,
        repoRoot: policyStore.repoRoot,
        authRequired: Boolean(apiToken),
        retainedEventCount: tail.events.length,
        invalidLineCount: tail.invalidLineCount,
        lastReadAt: tail.lastReadAt,
        readError: tail.readError,
      })
      return
    }

    if (url.pathname === '/events') {
      const limit = parsePositiveInt(url.searchParams.get('limit'), 100)
      const type = url.searchParams.get('type') || ''
      writeJson(response, 200, {
        path: tail.eventLogPath,
        retainedEventCount: tail.events.length,
        invalidLineCount: tail.invalidLineCount,
        limit,
        type: type || null,
        events: tail.recent({ limit, type }),
      })
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
    server.close(() => process.exit(0))
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main()
}

export { EventTail, createServer, parseArgs, resolveGuardEventLogPath, resolveGuardStateDir }
