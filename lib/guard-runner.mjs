#!/usr/bin/env node

import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import dns from 'node:dns/promises'
import { spawn, spawnSync } from 'node:child_process'
import path from 'node:path'
import readline from 'node:readline/promises'
import { fileURLToPath } from 'node:url'

import { startHttpProxy, startSocksProxy, createDomainFilter, buildProxyEnv } from './guard-network.mjs'
import { generateProfile } from './guard-manager.mjs'
import { sandboxLogTag, startSandboxDenialStream } from './guard-sandbox-log.mjs'
import { assertLinuxBubblewrapSupported, buildBubblewrapArgs } from './guard-bubblewrap.mjs'

const [, , runtimeConfigPath, guardProfilePath, ...commandArgs] = process.argv
const guardLibDir = path.dirname(fileURLToPath(import.meta.url))
const guardRepoRoot = path.dirname(guardLibDir)

if (!runtimeConfigPath || !guardProfilePath || commandArgs.length === 0) {
  console.error(
    'usage: guard-runner.mjs <runtime-config.json> <profile.sb> <command> [args...]',
  )
  process.exit(2)
}

const cfg = JSON.parse(fs.readFileSync(runtimeConfigPath, 'utf8'))
const network = cfg.network || {}
const askNetworkEnabled = network.ask === true
const learnHttpRulesEnabled = network.learnHttpRules !== false
const upgradeDomainAllowsEnabled = network.upgradeDomainAllows !== false
const networkBackend = network.backend || 'guard'
const daemonPolicyEnabled = network.decisionMode === 'guardd' || network.useGuarddPolicy === true
const daemonDecisionTimeoutMs = Math.max(
  1,
  Number.parseInt(String(network.decisionTimeoutMs || process.env.GUARD_DAEMON_DECISION_TIMEOUT_MS || 300000), 10) || 300000,
)
const tlsInspection = network.tlsInspection && typeof network.tlsInspection === 'object'
  ? network.tlsInspection
  : {}
const tlsInspectionEnabled = typeof tlsInspection.enabled === 'boolean'
  ? tlsInspection.enabled
  : networkBackend === 'iron-proxy'
const defaultTlsCaDays = 90
const defaultTlsLeafDays = 30
const hasProxyNetworkRules =
  (Array.isArray(network.allowedDomains) &&
    network.allowedDomains.length > 0) ||
  (Array.isArray(network.httpRules) && network.httpRules.length > 0)
const proxyEnabled =
  !cfg.networkUnrestricted &&
  (process.platform === 'linux'
    ? hasProxyNetworkRules
    : (askNetworkEnabled || hasProxyNetworkRules))
const runtimeBackend = process.platform === 'linux' ? 'bubblewrap' : 'sandbox-exec'

const cleanups = []
const networkLogPath = process.env.GUARD_NETWORK_LOG || ''
const eventLogPath = process.env.GUARD_EVENT_LOG || ''
const discoveryReportPath = process.env.GUARD_DISCOVERY_REPORT || ''
const discoveryStderr = []
const discoveryStdout = []
const EVENT_SCHEMA_VERSION = 1
const sandboxDenialLogEnabled =
  process.platform === 'darwin' &&
  process.env.GUARD_SANDBOX_DENIAL_LOG !== '0' &&
  process.env.GUARD_SANDBOX_DENIAL_LOG !== 'false'
const sandboxDenialLogStartupMs = Math.max(
  0,
  Number.parseInt(String(process.env.GUARD_SANDBOX_DENIAL_LOG_STARTUP_MS || 100), 10) || 0,
)
const sandboxDenialLogLevel = String(process.env.GUARD_SANDBOX_DENIAL_LOGS || 'actionable').toLowerCase()
const runSandboxLogTag = process.env.GUARD_SANDBOX_LOG_TAG || sandboxLogTag({
  runDir: process.env.GUARD_RUN_DIR,
})

const shouldRecordSandboxDenial = (denial) => {
  if (sandboxDenialLogLevel === 'all' || sandboxDenialLogLevel === 'verbose') return true
  if (denial.notificationRecommended || denial.severity === 'high' || denial.severity === 'medium') return true
  if (denial.category === 'process') return true
  if (denial.category === 'network' && denial.target && !String(denial.target).startsWith('/')) return true
  return false
}

const resolveGuardStateDir = () => {
  if (process.env.GUARD_STATE_DIR) return path.resolve(process.env.GUARD_STATE_DIR)
  if (process.env.GUARD_REAL_HOME) {
    return path.join(process.env.GUARD_REAL_HOME, 'Library', 'Application Support', 'guard')
  }
  if (process.env.HOME) {
    return path.join(process.env.HOME, 'Library', 'Application Support', 'guard')
  }
  return path.resolve('/tmp/guard-state')
}

const temporaryHttpDecisionPath = () =>
  process.env.GUARD_TEMP_HTTP_DECISIONS
    ? path.resolve(process.env.GUARD_TEMP_HTTP_DECISIONS)
    : path.join(resolveGuardStateDir(), 'temporary-http-decisions.json')

const closeAll = async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop()
    try {
      await cleanup()
    } catch {}
  }
}

const appendJsonLine = (target, value) => {
  if (!target) return
  try {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.appendFileSync(target, `${JSON.stringify(value)}\n`)
  } catch {}
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const commandSummary = commandArgs
  .map((part) => String(part))
  .join(' ')

const resolveExecutablePath = (command = '') => {
  if (!command) return ''
  if (path.isAbsolute(command)) return command
  const pathEntries = (process.env.PATH || '').split(path.delimiter).filter(Boolean)
  for (const entry of pathEntries) {
    const candidate = path.join(entry, command)
    try {
      if (fs.statSync(candidate).isFile()) return candidate
    } catch {
      // Try the next PATH entry.
    }
  }
  return ''
}

const executablePath = resolveExecutablePath(String(commandArgs[0] || ''))
const executablePaths = (() => {
  const values = [executablePath].filter(Boolean)
  try {
    const real = fs.realpathSync(executablePath)
    if (real && !values.includes(real)) values.push(real)
  } catch {}
  if (process.platform === 'darwin' && executablePath === '/bin/sh' && !values.includes('/bin/bash')) {
    values.push('/bin/bash')
  }
  return values
})()

const executableIdentity = (() => {
  if (!executablePath) return null
  let sha256 = ''
  try {
    sha256 = crypto.createHash('sha256').update(fs.readFileSync(executablePath)).digest('hex')
  } catch {}
  let signature = {}
  if (process.platform === 'darwin') {
    const result = spawnSync('/usr/bin/codesign', ['-dv', '--verbose=4', executablePath], {
      encoding: 'utf8',
    })
    const text = `${result.stdout || ''}\n${result.stderr || ''}`
    const capture = (pattern) => text.match(pattern)?.[1] || ''
    signature = {
      identifier: capture(/^Identifier=(.+)$/m),
      teamId: capture(/^TeamIdentifier=(.+)$/m),
      authority: capture(/^Authority=(.+)$/m),
      signed: result.status === 0,
    }
  }
  return {
    path: executablePath,
    name: path.basename(executablePath),
    sha256,
    signature,
  }
})()

const launcherContextPayload = () => ({
  launcherApp: process.env.GUARD_LAUNCHER_APP || '',
  launcherProcess: process.env.GUARD_LAUNCHER_PROCESS || '',
  launcherPid: Number(process.env.GUARD_LAUNCHER_PID || 0) || 0,
  parentChain: process.env.GUARD_PARENT_CHAIN || '',
})

const baseEvent = (type, value = {}) => ({
  schemaVersion: EVENT_SCHEMA_VERSION,
  at: new Date().toISOString(),
  type,
  profile: process.env.GUARD_PROFILE || process.env.GUARD_DISCOVERY_PROFILE || '',
  projectDir: process.env.GUARD_PROJECT_DIR || '',
  cwd: process.env.GUARD_CWD || process.cwd(),
  runDir: process.env.GUARD_RUN_DIR || '',
  command: commandSummary,
  processPath: executablePath,
  processIdentity: executableIdentity,
  ...launcherContextPayload(),
  ...value,
})

const recordGuardEvent = (type, value = {}) => {
  appendJsonLine(eventLogPath, baseEvent(type, value))
}

const recordNetworkDecision = (event) => {
  const row = baseEvent('network.decision', {
    backend: networkBackend,
    ...event,
  })
  appendJsonLine(networkLogPath, row)
  appendJsonLine(eventLogPath, row)
}

const recordNetworkFlow = (event) => {
  const row = baseEvent('network.flow', {
    backend: networkBackend,
    ...event,
  })
  appendJsonLine(networkLogPath, row)
  appendJsonLine(eventLogPath, row)
}

const safeNumber = (value, fallback = 0) => {
  const number = Number(value)
  return Number.isFinite(number) ? number : fallback
}

const redactedAuditTransformSummary = (transforms = []) => {
  if (!Array.isArray(transforms)) return ''
  return transforms
    .map((transform) => {
      const name = String(transform?.name || '').trim()
      const action = String(transform?.action || '').trim()
      const annotations = transform?.annotations && typeof transform.annotations === 'object'
        ? Object.keys(transform.annotations).sort().join(',')
        : ''
      return [name, action, annotations ? `annotations:${annotations}` : ''].filter(Boolean).join(':')
    })
    .filter(Boolean)
    .join(' ')
}

const recordIronProxyAudit = (auditLine) => {
  let parsed
  try {
    parsed = JSON.parse(auditLine)
  } catch {
    return false
  }
  if (!parsed || parsed.msg !== 'request') return false
  const audit = parsed.audit && typeof parsed.audit === 'object' ? parsed.audit : parsed
  const host = String(audit.host || '').trim()
  if (!host) return true
  const action = String(audit.action || '').toLowerCase()
  const denied = action === 'reject' || action === 'deny' || Boolean(parsed.rejected_by)
  const errored = action === 'error' || Boolean(parsed.error)
  const statusCode = safeNumber(audit.status_code || parsed.status_code, 0)
  const method = String(audit.method || '').trim()
  const requestPath = String(audit.path || '').trim()
  const transforms = [
    redactedAuditTransformSummary(parsed.request_transforms),
    redactedAuditTransformSummary(parsed.response_transforms),
  ].filter(Boolean).join(' ')
  recordNetworkFlow({
    phase: 'closed',
    protocol: audit.mode === 'https' || audit.sni ? 'https' : 'http',
    transport: 'iron-proxy',
    host,
    method,
    path: requestPath,
    status: errored ? 'error' : denied ? 'denied' : 'allowed',
    statusCode,
    durationMs: safeNumber(audit.duration_ms || parsed.duration_ms, 0),
    rejectedBy: parsed.rejected_by || '',
    detail: transforms,
  })
  return true
}

const ironProxyLogMode = () =>
  String(network.proxyLogs ?? process.env.GUARD_IRON_PROXY_LOGS ?? process.env.GUARD_PROXY_LOGS ?? 'errors')
    .trim()
    .toLowerCase()

const shouldPrintIronProxyLog = (line) => {
  const mode = ironProxyLogMode()
  if (['1', 'true', 'yes', 'all', 'verbose', 'debug'].includes(mode)) return true
  if (['0', 'false', 'no', 'none', 'off', 'quiet'].includes(mode)) return false
  try {
    const parsed = JSON.parse(line)
    const level = String(parsed.level || '').toLowerCase()
    return level === 'warn' || level === 'warning' || level === 'error' || level === 'fatal'
  } catch {
    return true
  }
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

const ruleIdFor = (rule) =>
  `rule_${crypto.createHash('sha256').update(stableJson(rule)).digest('hex').slice(0, 16)}`

const canonicalHttpRule = (rule = {}) => {
  const normalized = normalizeRule(rule)
  const canonical = normalized.host
    ? { host: normalized.host }
    : normalized.cidr
      ? { cidr: normalized.cidr }
      : {}
  if (normalized.methods.length > 0) canonical.methods = [...new Set(normalized.methods)]
  if (normalized.paths.length > 0) canonical.paths = [...new Set(normalized.paths)]
  return canonical
}

const persistHttpRule = (rule, reason) => {
  if (!learnHttpRulesEnabled) return false
  const configPath = process.env.GUARD_CONFIG || ''
  if (!configPath) return false
  try {
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'))
    if (!raw.network || typeof raw.network !== 'object' || Array.isArray(raw.network)) {
      raw.network = {}
    }
    if (!Array.isArray(raw.network.httpRules)) raw.network.httpRules = []
    const canonical = canonicalHttpRule(rule)
    const key = stableJson(canonical)
    if (raw.network.httpRules.some((entry) => stableJson(canonicalHttpRule(entry)) === key)) {
      return false
    }
    raw.network.httpRules.push(canonical)
    fs.writeFileSync(configPath, `${JSON.stringify(raw, null, 2)}\n`)
    recordGuardEvent('guard.profile.rule_learned', {
      backend: 'iron-proxy',
      field: 'network.httpRules',
      configPath,
      rule: canonical,
      ruleId: ruleIdFor(canonical),
      reason,
    })
    return true
  } catch (error) {
    recordGuardEvent('guard.profile.rule_learn_failed', {
      backend: 'iron-proxy',
      field: 'network.httpRules',
      configPath,
      rule,
      error: error.message,
      reason,
    })
    return false
  }
}

const formatHostPort = (host, port) =>
  Number.isInteger(port) && port > 0 ? `${host}:${port}` : host

const normalizeNetworkPort = (port, field = 'network.allowedRawTcp.port') => {
  const value = Number(port)
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`guard: invalid ${field} entry: ${port}`)
  }
  return value
}

const rawTcpRuleDescription = (rule = {}) => {
  const port = rule.port === undefined ? '?' : rule.port
  return rule.ip
    ? `${rule.ip}:${port}`
    : `${rule.host || '<missing-host>'}:${port}`
}

const shellCommands = new Set(['bash', 'dash', 'fish', 'ksh', 'sh', 'zsh'])

const isInteractiveShellCommand = (command) =>
  shellCommands.has(path.basename(command || ''))

const escapeAppleScriptString = (value) =>
  String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')

const resolveAskUi = () => {
  if (process.env.GUARD_ASK_NETWORK_UI) {
    return process.env.GUARD_ASK_NETWORK_UI
  }
  return isInteractiveShellCommand(commandArgs[0]) ? 'dialog' : 'tty'
}

const resolveAllowedRawTcp = async (rules = []) => {
  if (!Array.isArray(rules) || rules.length === 0) return []

  const resolved = []
  for (const [index, rule] of rules.entries()) {
    const port = normalizeNetworkPort(rule?.port, `network.allowedRawTcp[${index}].port`)
    const reason = typeof rule?.reason === 'string' ? rule.reason : ''
    const ruleId = ruleIdFor({ ...rule, port })

    if (typeof rule?.ip === 'string' && rule.ip.trim()) {
      const ip = rule.ip.trim()
      if (net.isIP(ip) === 0) {
        throw new Error(`guard: invalid network.allowedRawTcp[${index}].ip entry: ${ip}`)
      }
      resolved.push({ ruleId, ip, port, reason, source: 'ip' })
      continue
    }

    if (typeof rule?.host === 'string' && rule.host.trim()) {
      const host = rule.host.trim()
      if (rule.resolveAtLaunch !== true) {
        throw new Error(
          `guard: network.allowedRawTcp[${index}] uses host ${host}; set resolveAtLaunch: true or provide an explicit ip`,
        )
      }
      const addresses = [...new Set((await dns.lookup(host, { all: true })).map((row) => row.address))]
      if (addresses.length === 0) {
        throw new Error(`guard: network.allowedRawTcp[${index}] host resolved to no addresses: ${host}`)
      }
      recordGuardEvent('network.raw_tcp_resolved', {
        ruleId,
        host,
        port,
        addresses,
        reason,
      })
      for (const ip of addresses) {
        resolved.push({ ruleId, host, ip, port, reason, source: 'host' })
      }
      continue
    }

    throw new Error(
      `guard: network.allowedRawTcp[${index}] must include ip or host: ${rawTcpRuleDescription(rule)}`,
    )
  }

  return resolved
}

const isGraphicalAskUi = () => ['dialog', 'osascript', 'native'].includes(resolveAskUi())
const isDialogAskUi = () => ['dialog', 'osascript'].includes(resolveAskUi())
const resolveAskHelper = () => process.env.GUARD_ASK_NETWORK_HELPER || ''

let networkAskQueue = Promise.resolve()

const askNetworkAccessInTerminal = async (target) => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  })
  try {
    const reply = await rl.question(
      `guard: allow network access to ${target} for this run? [y/N] `,
    )
    return /^(y|yes)$/i.test(reply.trim())
  } finally {
    rl.close()
  }
}

const askNetworkAccessInDialog = async (target) => {
  const message = escapeAppleScriptString(
    `Allow network access to ${target} for this Guard run?\n\nThis creates a temporary allow decision for the current run only.`,
  )
  const script = [
    `display dialog "${message}"`,
    'buttons {"Deny", "Allow Once"}',
    'default button "Deny"',
    'cancel button "Deny"',
    'with title "Guard Network Access"',
  ].join(' ')

  const child = spawn('/usr/bin/osascript', ['-e', script], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  let stdout = ''
  child.stdout.on('data', (chunk) => {
    stdout += chunk
  })

  return await new Promise((resolve) => {
    child.on('error', () => resolve(false))
    child.on('exit', (code) => {
      resolve(code === 0 && /button returned:Allow Once/.test(stdout))
    })
  })
}

const runNativeAskHelper = async (mode, payload) => {
  const helper = resolveAskHelper()
  if (!helper) return { action: 'deny' }
  const child = spawn(helper, [mode, '--json', JSON.stringify(payload)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  child.stdout.on('data', (chunk) => {
    stdout += chunk
  })
  return await new Promise((resolve) => {
    child.on('error', () => resolve({ action: 'deny' }))
    child.on('exit', (code) => {
      if (code !== 0) {
        resolve({ action: 'deny' })
        return
      }
      try {
        const parsed = JSON.parse(stdout)
        resolve(parsed && typeof parsed === 'object' ? parsed : { action: 'deny' })
      } catch {
        resolve({ action: 'deny' })
      }
    })
  })
}

const askNetworkAccessInNative = async (target, host, port) => {
  const result = await runNativeAskHelper('ask-network', {
    target,
    host,
    port,
    profile: process.env.GUARD_PROFILE || '',
    projectDir: process.env.GUARD_PROJECT_DIR || '',
    runDir: process.env.GUARD_RUN_DIR || '',
    command: commandSummary,
    ...launcherContextPayload(),
  })
  return {
    action: result.action === 'allow' ? 'allow' : 'deny',
    duration: result.duration || 'run',
  }
}

const askNetworkAccessNow = async (host, port) => {
  const target = formatHostPort(host, port)
  if (daemonPolicyEnabled) {
    try {
      const decision = await requestGuarddDecision({
        host,
        port,
        protocol: 'tcp',
        reason: 'daemon-network-policy',
      })
      return {
        action: decision.action === 'allow' ? 'allow' : 'deny',
        duration: decision.duration || 'once',
      }
    } catch (error) {
      if (network.nativePromptFallback === true && resolveAskUi() === 'native') {
        return await askNetworkAccessInNative(target, host, port)
      }
      console.error(`guard: blocked network access to ${target}; guardd policy unavailable: ${error.message}`)
      return false
    }
  }

  if (!isGraphicalAskUi() && !(process.stdin.isTTY && process.stderr.isTTY)) {
    console.error(`guard: blocked network access to ${target}; --ask-network requires an interactive terminal`)
    return false
  }

  if (resolveAskUi() === 'native') {
    return await askNetworkAccessInNative(target, host, port)
  }

  if (isDialogAskUi()) {
    return await askNetworkAccessInDialog(target)
  }

  return await askNetworkAccessInTerminal(target)
}

const askNetworkAccess = (host, port) => {
  const decision = networkAskQueue.then(
    () => askNetworkAccessNow(host, port),
    () => askNetworkAccessNow(host, port),
  )
  networkAskQueue = decision.catch(() => {})
  return decision
}

const getFreeLoopbackPort = async () =>
  await new Promise((resolve, reject) => {
    const server = http.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address ? address.port : 0
      server.close((error) => (error ? reject(error) : resolve(port)))
    })
  })

const waitForLoopbackPort = async (port, timeoutMs = 5000) => {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    const ok = await new Promise((resolve) => {
      const socket = net.connect({ host: '127.0.0.1', port })
      socket.setTimeout(250)
      socket.once('connect', () => {
        socket.destroy()
        resolve(true)
      })
      socket.once('timeout', () => {
        socket.destroy()
        resolve(false)
      })
      socket.once('error', () => resolve(false))
    })
    if (ok) return
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`timed out waiting for iron-proxy on localhost:${port}`)
}

const quoteYaml = (value) =>
  JSON.stringify(String(value))

const yamlList = (values = [], indent = 8) => {
  const prefix = ' '.repeat(indent)
  return values.length > 0
    ? values.map((value) => `${prefix}- ${quoteYaml(value)}`).join('\n')
    : `${prefix}[]`
}

const normalizeRule = (rule = {}) => ({
  host: typeof rule.host === 'string' ? rule.host : '',
  cidr: typeof rule.cidr === 'string' ? rule.cidr : '',
  methods: Array.isArray(rule.methods) ? rule.methods.map((value) => String(value).toUpperCase()) : [],
  paths: Array.isArray(rule.paths) ? rule.paths.map(String) : [],
})

const appendRuleYaml = (lines, rule, indent = 8) => {
  const normalized = normalizeRule(rule)
  const prefix = ' '.repeat(indent)
  lines.push(`${prefix}- ${normalized.host ? `host: ${quoteYaml(normalized.host)}` : `cidr: ${quoteYaml(normalized.cidr)}`}`)
  if (normalized.methods.length > 0) {
    lines.push(`${prefix}  methods:`)
    lines.push(yamlList(normalized.methods, indent + 4))
  }
  if (normalized.paths.length > 0) {
    lines.push(`${prefix}  paths:`)
    lines.push(yamlList(normalized.paths, indent + 4))
  }
}

const secretInjectionEntries = () => {
  const entries = Array.isArray(network.secretInjection)
    ? network.secretInjection
    : Array.isArray(network.secrets)
      ? network.secrets
      : []
  return entries.filter((entry) => entry && typeof entry === 'object')
}

const yamlScalar = (lines, key, value, indent = 10) => {
  if (value === undefined || value === null || value === '') return
  const prefix = ' '.repeat(indent)
  lines.push(`${prefix}${key}: ${typeof value === 'boolean' ? value : quoteYaml(value)}`)
}

const appendSecretSourceYaml = (lines, source = {}, indent = 12) => {
  const prefix = ' '.repeat(indent)
  const type = source.type || 'env'
  lines.push(`${prefix}type: ${quoteYaml(type)}`)
  for (const key of ['var', 'secret_id', 'region', 'json_key', 'ttl']) {
    if (source[key]) lines.push(`${prefix}${key}: ${quoteYaml(source[key])}`)
  }
}

const appendSecretInjectionYaml = (lines, entry, indent = 8) => {
  const prefix = ' '.repeat(indent)
  const source = entry.source && typeof entry.source === 'object'
    ? entry.source
    : { type: 'env', var: entry.env || entry.var || entry.name }
  const proxyValue = entry.proxyValue || entry.proxy_value || entry.proxyToken
  if (!proxyValue) {
    throw new Error(`network.secretInjection entry ${entry.name || source.var || ''} requires proxyValue`)
  }

  lines.push(`${prefix}- source:`)
  appendSecretSourceYaml(lines, source, indent + 4)
  lines.push(`${prefix}  proxy_value: ${quoteYaml(proxyValue)}`)
  const headers = Array.isArray(entry.matchHeaders)
    ? entry.matchHeaders
    : Array.isArray(entry.match_headers)
      ? entry.match_headers
      : ['Authorization']
  lines.push(`${prefix}  match_headers:`)
  lines.push(yamlList(headers, indent + 4))
  yamlScalar(lines, 'match_body', entry.matchBody === true || entry.match_body === true, indent + 2)
  yamlScalar(lines, 'require', entry.require === true, indent + 2)
  const rules = Array.isArray(entry.rules) && entry.rules.length > 0
    ? entry.rules
    : [{ host: entry.host, methods: entry.methods, paths: entry.paths }]
  lines.push(`${prefix}  rules:`)
  for (const rule of rules) {
    appendRuleYaml(lines, rule, indent + 4)
  }
}

const buildIronProxyConfig = ({ httpPort, socksPort, caCert, caKey, policyEndpoint }) => {
  const allowedDomains = Array.isArray(network.allowedDomains) ? network.allowedDomains : []
  const httpRules = Array.isArray(network.httpRules) ? network.httpRules : []
  const secrets = secretInjectionEntries()
  const lines = [
    'dns:',
    '  listen: "off"',
    'proxy:',
    `  http_listen: "127.0.0.1:${httpPort}"`,
    '  https_listen: "off"',
    `  tunnel_listen: "127.0.0.1:${socksPort}"`,
    `  max_request_body_bytes: ${Number(network.maxRequestBodyBytes || 1048576)}`,
    `  max_response_body_bytes: ${Number(network.maxResponseBodyBytes || 0)}`,
    'tls:',
    `  ca_cert: ${quoteYaml(caCert)}`,
    `  ca_key: ${quoteYaml(caKey)}`,
    'transforms:',
  ]

  if (askNetworkEnabled) {
    lines.push('  - name: interactive_policy')
    lines.push('    config:')
    lines.push(`      endpoint: ${quoteYaml(policyEndpoint)}`)
    lines.push('      timeout_ms: 300000')
  } else {
    lines.push('  - name: allowlist')
    lines.push('    config:')
    if (allowedDomains.length > 0) {
      lines.push('      domains:')
      lines.push(yamlList(allowedDomains, 8))
    }
    if (httpRules.length > 0) {
      lines.push('      rules:')
      for (const rule of httpRules) {
        appendRuleYaml(lines, rule, 8)
      }
    }
  }

  if (secrets.length > 0) {
    lines.push('  - name: secrets')
    lines.push('    config:')
    lines.push('      secrets:')
    for (const entry of secrets) {
      appendSecretInjectionYaml(lines, entry, 8)
    }
  }

  lines.push('metrics:', '  listen: "off"', 'log:', '  level: "info"')
  return `${lines.join('\n')}\n`
}

const guarddBaseURL = () => {
  const configured = process.env.GUARD_DAEMON_URL || process.env.GUARDD_URL
  if (configured) return configured.replace(/\/+$/, '')
  const token = process.env.GUARDD_API_TOKEN || process.env.GUARD_DAEMON_TOKEN || ''
  if (!token) return ''
  const host = process.env.GUARDD_HOST || '127.0.0.1'
  const port = process.env.GUARDD_PORT || '8765'
  return `http://${host}:${port}`
}

const requestGuarddJson = (pathname, { method = 'GET', body = null, timeoutMs = 1200 } = {}) =>
  new Promise((resolve, reject) => {
    const base = guarddBaseURL()
    if (!base) {
      reject(new Error('guardd URL/token not configured'))
      return
    }
    const url = new URL(pathname, `${base}/`)
    const payload = body ? Buffer.from(JSON.stringify(body)) : null
    const req = http.request(
      url,
      {
        method,
        headers: {
          accept: 'application/json',
          ...(payload ? { 'content-type': 'application/json', 'content-length': String(payload.length) } : {}),
          ...(process.env.GUARDD_API_TOKEN || process.env.GUARD_DAEMON_TOKEN
            ? { authorization: `Bearer ${process.env.GUARDD_API_TOKEN || process.env.GUARD_DAEMON_TOKEN}` }
            : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          let json = {}
          try {
            json = text ? JSON.parse(text) : {}
          } catch {}
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(json)
            return
          }
          reject(new Error(json.message || json.error || `guardd returned ${res.statusCode}`))
        })
      },
    )
    req.on('timeout', () => req.destroy(new Error('guardd request timed out')))
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const alertFromList = (list, id) =>
  Array.isArray(list?.alerts)
    ? list.alerts.find((alert) => alert?.id === id) || null
    : null

const waitForGuarddAlertDecision = async (alertId, timeoutMs = daemonDecisionTimeoutMs) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const resolved = alertFromList(
      await requestGuarddJson('/alerts/pending?status=resolved&limit=100', { timeoutMs: 2500 }).catch(() => null),
      alertId,
    )
    if (resolved?.decision?.action) return resolved

    const expired = alertFromList(
      await requestGuarddJson('/alerts/pending?status=expired&limit=100', { timeoutMs: 2500 }).catch(() => null),
      alertId,
    )
    if (expired) return expired

    await sleep(75)
  }
  return null
}

const requestGuarddDecision = async ({
  host,
  port = 0,
  method = '',
  path: requestPath = '',
  protocol = '',
  reason = 'daemon-policy',
  suggestedAction = 'allow',
  suggestedDuration = 'session',
}) => {
  const alert = await requestGuarddJson('/alerts/pending', {
    method: 'POST',
    timeoutMs: 2500,
    body: {
      profile: process.env.GUARD_PROFILE || '',
      host,
      port,
      method,
      path: requestPath,
      protocol,
      command: commandSummary,
      projectDir: process.env.GUARD_PROJECT_DIR || '',
      runDir: process.env.GUARD_RUN_DIR || '',
      ...launcherContextPayload(),
      reason,
      suggestedAction,
      suggestedDuration,
      timeoutMs: daemonDecisionTimeoutMs,
    },
  })
  if (alert?.decision?.action) {
    return {
      action: alert.decision.action,
      duration: alert.decision.duration || 'once',
      expiresAt: alert.decision.expiresAt || alert.decision.decisionExpiresAt || '',
      rule: alert.decision.rule || null,
      ruleId: alert.decision.ruleId || '',
      alertId: '',
      reason: alert.cached ? 'guardd-cached-decision' : 'guardd-alert-decision',
    }
  }
  const pending = alert?.alert
  if (!pending?.id) {
    throw new Error('guardd did not return a pending alert id')
  }
  recordGuardEvent('guardd.alert.pending', {
    backend: 'guardd',
    alertId: pending.id,
    host,
    port,
    method,
    path: requestPath,
    protocol,
    reason,
  })
  const resolved = await waitForGuarddAlertDecision(pending.id)
  if (!resolved?.decision?.action) {
    recordGuardEvent('guardd.alert.timeout', {
      backend: 'guardd',
      alertId: pending.id,
      host,
      port,
      method,
      path: requestPath,
      protocol,
      timeoutMs: daemonDecisionTimeoutMs,
    })
    return { action: 'deny', duration: 'once', alertId: pending.id, reason: 'guardd-decision-timeout' }
  }
  return {
    action: resolved.decision.action,
    duration: resolved.decision.duration || 'once',
    expiresAt: resolved.decision.expiresAt || resolved.expiresAt || '',
    rule: resolved.decision.rule || null,
    ruleId: resolved.decision.ruleId || '',
    alertId: pending.id,
    reason: resolved.status === 'expired' ? 'guardd-alert-expired' : 'guardd-alert-decision',
  }
}

const ironProxyWarmHosts = () => {
  const hosts = [
    ...(Array.isArray(network.allowedDomains) ? network.allowedDomains : []),
    ...(Array.isArray(network.httpRules) ? network.httpRules.map((rule) => rule?.host || rule?.cidr || '') : []),
  ]
    .map((host) => String(host || '').trim().toLowerCase())
    .filter((host) => host && !host.includes('*') && !host.includes('/'))
  return [...new Set(hosts)].slice(0, 100)
}

const resolveGuarddIronProxyCA = async () => {
  if (tlsInspection.useGuarddCa === false || !guarddBaseURL()) return null
  const activeCa = await requestGuarddJson('/tls/ca', {
    method: 'POST',
    body: { action: 'generate', days: Number(tlsInspection.caDays || defaultTlsCaDays), commonName: 'Guard iron-proxy CA' },
  })
  const certificatePath = activeCa?.paths?.certificatePath
  const privateKeyPath = activeCa?.paths?.privateKeyPath
  if (!certificatePath || !privateKeyPath || !fs.existsSync(certificatePath) || !fs.existsSync(privateKeyPath)) {
    throw new Error('guardd returned incomplete TLS CA metadata')
  }

  const warmed = []
  const failed = []
  for (const host of ironProxyWarmHosts()) {
    try {
      const result = await requestGuarddJson('/tls/cert', {
        method: 'POST',
        body: { host, days: Number(tlsInspection.leafDays || defaultTlsLeafDays) },
      })
      warmed.push({ host, path: result?.paths?.certificatePath || '' })
    } catch (error) {
      failed.push({ host, error: error.message })
    }
  }
  recordGuardEvent('tls.cert_cache_warmed', {
    backend: 'iron-proxy',
    caCert: certificatePath,
    warmed,
    failed,
    globalTrustManaged: false,
  })
  return { caCert: certificatePath, caKey: privateKeyPath, source: 'guardd' }
}

const resolveIronProxy = () => {
  if (process.env.GUARD_IRON_PROXY_BIN) {
    return { command: process.env.GUARD_IRON_PROXY_BIN, argsPrefix: [], cwd: process.cwd() }
  }
  const packagedBin = path.resolve(guardRepoRoot, 'bin/iron-proxy')
  if (fs.existsSync(packagedBin)) {
    return { command: packagedBin, argsPrefix: [], cwd: guardRepoRoot }
  }
  const siblingRepo = path.resolve(guardRepoRoot, '..', 'iron-proxy')
  const siblingBin = path.join(siblingRepo, 'iron-proxy')
  if (fs.existsSync(siblingBin)) {
    return { command: siblingBin, argsPrefix: [], cwd: siblingRepo }
  }
  if (fs.existsSync(path.join(siblingRepo, 'go.mod'))) {
    return { command: 'go', argsPrefix: ['run', './cmd/iron-proxy'], cwd: siblingRepo }
  }
  const command = spawnSync('/bin/sh', ['-lc', 'command -v iron-proxy'], {
    encoding: 'utf8',
  }).stdout.trim()
  if (command) {
    return { command, argsPrefix: [], cwd: process.cwd() }
  }
  throw new Error('network.backend=iron-proxy requires GUARD_IRON_PROXY_BIN, a sibling ../iron-proxy checkout, or iron-proxy on PATH')
}

const generateIronProxyCA = (ironProxy, caDir) => {
  fs.rmSync(caDir, { force: true, recursive: true })
  fs.mkdirSync(caDir, { recursive: true })
  const result = spawnSync(
    ironProxy.command,
    [...ironProxy.argsPrefix, 'generate-ca', '--outdir', caDir, '--name', 'guard iron-proxy CA', '--expiry-hours', '24'],
    {
      cwd: ironProxy.cwd,
      encoding: 'utf8',
    },
  )
  if (result.error || result.status !== 0) {
    throw new Error(`failed to generate iron-proxy CA: ${result.error?.message || result.stderr || result.stdout}`)
  }
}

const pathMatches = (pattern, requestPath) => {
  if (pattern === '*' || pattern === '/*') return true
  if (pattern.endsWith('/*')) {
    const base = pattern.slice(0, -2)
    return requestPath === base || requestPath.startsWith(`${base}/`)
  }
  return pattern === requestPath
}

const hostMatches = (pattern, requestHost) => {
  if (!pattern) return true
  if (pattern === requestHost) return true
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1)
    return requestHost.endsWith(suffix) && requestHost.length > suffix.length
  }
  return false
}

const ruleMatchesRequest = (rule, request) => {
  const normalized = normalizeRule(rule)
  if (normalized.host && !hostMatches(normalized.host, request.host)) return false
  if (normalized.methods.length > 0 && !normalized.methods.includes(request.method)) return false
  if (normalized.paths.length > 0 && !normalized.paths.some((pattern) => pathMatches(pattern, request.path))) return false
  return true
}

const wildcardPathFor = (requestPath) => {
  const parts = String(requestPath || '/').split('/').filter(Boolean)
  if (parts.length <= 1) return '/*'
  return `/${parts.slice(0, -1).join('/')}/*`
}

const durationToExpiresAt = (duration) => {
  const value = String(duration || 'run').toLowerCase()
  if (value === 'forever' || value === 'run' || value === 'session') return 0
  const match = /^(\d+)(s|m|h|d)$/.exec(value)
  if (!match) return 0
  const amount = Number(match[1])
  const unitMs = match[2] === 's' ? 1_000 : match[2] === 'm' ? 60_000 : match[2] === 'h' ? 3_600_000 : 86_400_000
  return Date.now() + amount * unitMs
}

const activeRuntimeRules = (rules) => {
  const now = Date.now()
  return rules.filter((rule) => !rule.expiresAt || rule.expiresAt > now)
}

const readTemporaryHttpDecisions = () => {
  try {
    const parsed = JSON.parse(fs.readFileSync(temporaryHttpDecisionPath(), 'utf8'))
    return Array.isArray(parsed?.decisions) ? parsed.decisions : []
  } catch {
    return []
  }
}

const writeTemporaryHttpDecisions = (decisions) => {
  const file = temporaryHttpDecisionPath()
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  fs.writeFileSync(file, JSON.stringify({
    schemaVersion: 1,
    updatedAt: new Date().toISOString(),
    decisions,
  }, null, 2))
}

const activeTemporaryHttpDecisions = () => {
  const now = Date.now()
  const active = readTemporaryHttpDecisions().filter((decision) =>
    decision &&
    decision.expiresAt &&
    Number.isFinite(Date.parse(decision.expiresAt)) &&
    Date.parse(decision.expiresAt) > now,
  )
  try {
    writeTemporaryHttpDecisions(active)
  } catch {}
  return active
}

const rememberTemporaryHttpDecision = ({ action, rule, duration, expiresAt, request, ruleId }) => {
  if (!rule || !expiresAt || expiresAt <= Date.now()) return
  const decision = {
    schemaVersion: 1,
    id: ruleId || ruleIdFor(rule),
    action,
    profile: process.env.GUARD_PROFILE || '',
    launcherApp: process.env.GUARD_LAUNCHER_APP || '',
    launcherProcess: process.env.GUARD_LAUNCHER_PROCESS || '',
    command: commandSummary,
    host: request.host,
    method: request.method,
    path: request.path,
    rule,
    duration: duration || '',
    expiresAt: new Date(expiresAt).toISOString(),
    createdAt: new Date().toISOString(),
  }
  const decisions = activeTemporaryHttpDecisions().filter((entry) =>
    !(entry.profile === decision.profile &&
      entry.launcherApp === decision.launcherApp &&
      entry.launcherProcess === decision.launcherProcess &&
      stableJson(normalizeRule(entry.rule || {})) === stableJson(normalizeRule(rule))),
  )
  decisions.push(decision)
  try {
    writeTemporaryHttpDecisions(decisions)
  } catch {}
}

const matchingTemporaryHttpDecision = (request) => {
  const profile = process.env.GUARD_PROFILE || ''
  const launcherApp = process.env.GUARD_LAUNCHER_APP || ''
  const launcherProcess = process.env.GUARD_LAUNCHER_PROCESS || ''
  return activeTemporaryHttpDecisions().find((decision) => {
    if (decision.profile !== profile) return false
    if (decision.launcherApp && decision.launcherApp !== launcherApp) return false
    if (decision.launcherProcess && decision.launcherProcess !== launcherProcess) return false
    return ruleMatchesRequest(decision.rule || {}, request)
  }) || null
}

const askHttpPolicyInTerminal = async (request, suggestedRule, { upgrade = false } = {}) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr })
  try {
    const reply = await rl.question(
      upgrade
        ? `guard: ${request.method} ${request.host}${request.path} is allowed by domain. Save narrower rule? [e]xact/[p]ath/[k]eep/[d]eny `
        : `guard: allow ${request.method} ${request.host}${request.path}? [e]xact/[p]ath/[h]ost/[d]eny `,
    )
    const choice = reply.trim().toLowerCase()
    if (upgrade && (choice === 'k' || choice === 'keep' || choice === '')) {
      return { action: 'allow', rule: { host: request.host }, persist: false, reason: 'domain-allow-kept' }
    }
    if (choice === 'h' || choice === 'host') {
      return { action: 'allow', rule: { host: request.host }, persist: false }
    }
    if (choice === 'p' || choice === 'path' || choice === 'w' || choice === 'wildcard') {
      return { action: 'allow', rule: suggestedRule, persist: true }
    }
    if (choice === 'e' || choice === 'exact' || choice === 'y' || choice === 'yes') {
      return {
        action: 'allow',
        rule: { host: request.host, methods: [request.method], paths: [request.path] },
        persist: true,
      }
    }
    return { action: 'deny' }
  } finally {
    rl.close()
  }
}

const askHttpPolicyInDialog = async (request, suggestedRule, { upgrade = false } = {}) => {
  const message = escapeAppleScriptString(
    upgrade
      ? `${request.method} ${request.host}${request.path} is currently allowed by domain.\n\nSave a narrower HTTP rule so Guard does not ask again for this path?`
      : `Allow ${request.method} ${request.host}${request.path}?\n\nExact allows only this method and path. Path allows ${suggestedRule.paths[0]}. Domain allows all proxied HTTP requests to this host for the current run.`,
  )
  const choices = upgrade
    ? '{"Deny", "Allow Exact", "Allow Path", "Keep Domain"}'
    : '{"Deny", "Allow Exact", "Allow Path", "Allow Domain"}'
  const script = [
    `set guardChoice to choose from list ${choices}`,
    `with prompt "${message}"`,
    'with title "Guard Egress Policy"',
    `default items {${upgrade ? '"Allow Path"' : '"Deny"'}}`,
    'OK button name "Apply"',
    'cancel button name "Deny"',
    'if guardChoice is false then',
    '  error number -128',
    'end if',
    'return item 1 of guardChoice',
  ].join(' ')
  const child = spawn('/usr/bin/osascript', ['-e', script], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  child.stdout.on('data', (chunk) => {
    stdout += chunk
  })
  return await new Promise((resolve) => {
    child.on('error', () => resolve({ action: 'deny' }))
    child.on('exit', (code) => {
      if (code !== 0) {
        resolve({ action: 'deny' })
      } else if (/Allow Domain|Keep Domain/.test(stdout)) {
        resolve({ action: 'allow', rule: { host: request.host }, persist: false, reason: 'domain-allow-kept' })
      } else if (/Allow Path/.test(stdout)) {
        resolve({ action: 'allow', rule: suggestedRule, persist: true })
      } else if (/Allow Exact/.test(stdout)) {
        resolve({
          action: 'allow',
          rule: { host: request.host, methods: [request.method], paths: [request.path] },
          persist: true,
        })
      } else {
        resolve({ action: 'deny' })
      }
    })
  })
}

const askHttpPolicyInNative = async (request, suggestedRule, { upgrade = false } = {}) => {
  const result = await runNativeAskHelper('ask-http-policy', {
    request,
    suggestedRule,
    upgradeDomainAllow: upgrade,
    profile: process.env.GUARD_PROFILE || '',
    projectDir: process.env.GUARD_PROJECT_DIR || '',
    runDir: process.env.GUARD_RUN_DIR || '',
    command: commandSummary,
  })
  if (result.action === 'allow' && result.rule && typeof result.rule === 'object') {
    return {
      action: 'allow',
      rule: result.rule,
      duration: result.duration || 'run',
      persist: result.persist === true || result.duration === 'forever',
      reason: result.reason || '',
    }
  }
  return { action: 'deny' }
}

const startPolicyDecisionServer = async () => {
  let runtimeRules = []
  const configuredRules = Array.isArray(network.httpRules) ? network.httpRules : []
  const configuredDomainRules = Array.isArray(network.allowedDomains)
    ? network.allowedDomains.map((host) => ({ host }))
    : []
  const configuredDeniedDomainRules = Array.isArray(network.deniedDomains)
    ? network.deniedDomains.map((host) => ({ host }))
    : []
  let queue = Promise.resolve()

  const decide = async (request) => {
    const method = String(request.method || '').toUpperCase()
    const normalized = {
      ...request,
      method,
      host: String(request.host || '').toLowerCase(),
      path: request.path || '/',
    }

    runtimeRules = activeRuntimeRules(runtimeRules)
    const cachedTemporaryDecision = matchingTemporaryHttpDecision(normalized)
    if (cachedTemporaryDecision) {
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: cachedTemporaryDecision.action === 'allow',
        reason: 'matched-temporary-http-decision',
        ruleId: cachedTemporaryDecision.id || ruleIdFor(cachedTemporaryDecision.rule || {}),
        rule: cachedTemporaryDecision.rule,
        duration: cachedTemporaryDecision.duration || '',
        expiresAt: cachedTemporaryDecision.expiresAt || '',
      })
      return {
        action: cachedTemporaryDecision.action === 'allow' ? 'allow' : 'deny',
        reason: 'matched-temporary-http-decision',
      }
    }

    const matchedRule = [...configuredRules, ...runtimeRules].find((rule) =>
      ruleMatchesRequest(rule, normalized),
    )
    if (matchedRule) {
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: true,
        reason: 'matched-rule',
        ruleId: ruleIdFor(matchedRule),
        rule: matchedRule,
      })
      return { action: 'allow', reason: 'matched-rule' }
    }

    const matchedDomainRule = configuredDomainRules.find((rule) =>
      ruleMatchesRequest(rule, normalized),
    )
    const matchedDeniedDomainRule = configuredDeniedDomainRules.find((rule) =>
      ruleMatchesRequest(rule, normalized),
    )

    const suggestedRule = {
      host: normalized.host,
      methods: [method],
      paths: [wildcardPathFor(normalized.path)],
    }

    const askForHttpRule = async ({ upgrade = false } = {}) => {
      if (!isGraphicalAskUi() && !(process.stdin.isTTY && process.stderr.isTTY)) {
        if (upgrade) {
          recordNetworkDecision({
            host: normalized.host,
            method,
            path: normalized.path,
            allowed: true,
            reason: 'domain-allow-upgrade-skipped-noninteractive',
            ruleId: ruleIdFor(matchedDomainRule),
            rule: matchedDomainRule,
            suggestedRule,
            suggestedRuleId: ruleIdFor(suggestedRule),
          })
          return { action: 'allow', reason: 'domain-allow-upgrade-skipped-noninteractive', suggestedRule }
        }
        recordNetworkDecision({
          host: normalized.host,
          method,
          path: normalized.path,
          allowed: false,
          reason: 'interactive-policy-noninteractive',
          suggestedRule,
          suggestedRuleId: ruleIdFor(suggestedRule),
        })
        return {
          action: 'deny',
          reason: '--ask-network requires an interactive terminal',
          suggestedRule,
        }
      }
      const ask = () =>
        resolveAskUi() === 'native'
          ? askHttpPolicyInNative(normalized, suggestedRule, { upgrade })
          : isDialogAskUi()
          ? askHttpPolicyInDialog(normalized, suggestedRule, { upgrade })
          : askHttpPolicyInTerminal(normalized, suggestedRule, { upgrade })
      const decision = queue.then(ask, ask)
      queue = decision.catch(() => {})
      const result = await decision
      if (result.action === 'allow' && result.rule) {
        const persisted = result.persist === true
          ? persistHttpRule(result.rule, upgrade ? 'upgrade-domain-allow' : 'interactive-policy')
          : false
        const expiresAt = persisted ? 0 : durationToExpiresAt(result.duration)
        runtimeRules.push({
          ...result.rule,
          expiresAt,
        })
        if (!persisted) {
          rememberTemporaryHttpDecision({
            action: 'allow',
            rule: result.rule,
            duration: result.duration || 'run',
            expiresAt,
            request: normalized,
            ruleId: ruleIdFor(result.rule),
          })
        }
        recordNetworkDecision({
          host: normalized.host,
          method,
          path: normalized.path,
          allowed: true,
          reason: result.reason || (upgrade ? 'domain-allow-upgraded' : 'interactive-policy'),
          ruleId: ruleIdFor(result.rule),
          suggestedRule: result.rule,
          duration: persisted ? 'forever' : result.duration || 'run',
          expiresAt: expiresAt ? new Date(expiresAt).toISOString() : '',
          rulePersisted: persisted,
          upgradedFromRule: upgrade ? matchedDomainRule : null,
        })
        return {
          action: 'allow',
          reason: result.reason || (upgrade ? 'domain-allow-upgraded' : 'interactive-policy'),
          suggestedRule: result.rule,
        }
      }
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: false,
        reason: upgrade ? 'domain-allow-upgrade-denied' : 'interactive-policy',
        suggestedRule,
        suggestedRuleId: ruleIdFor(suggestedRule),
        upgradedFromRule: upgrade ? matchedDomainRule : null,
      })
      return { action: 'deny', reason: upgrade ? 'domain-allow-upgrade-denied' : 'interactive-policy', suggestedRule }
    }

    if (matchedDeniedDomainRule) {
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: false,
        reason: 'matched-denied-domain-rule',
        ruleId: ruleIdFor(matchedDeniedDomainRule),
        rule: matchedDeniedDomainRule,
      })
      return { action: 'deny', reason: 'matched-denied-domain-rule' }
    }

    if (matchedDomainRule) {
      if (upgradeDomainAllowsEnabled && askNetworkEnabled) {
        return await askForHttpRule({ upgrade: true })
      }
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: true,
        reason: 'matched-domain-rule',
        ruleId: ruleIdFor(matchedDomainRule),
        rule: matchedDomainRule,
      })
      return { action: 'allow', reason: 'matched-domain-rule' }
    }

    if (daemonPolicyEnabled) {
      try {
        const result = await requestGuarddDecision({
          host: normalized.host,
          port: Number(normalized.port || 0),
          method,
          path: normalized.path,
          protocol: 'http',
          reason: 'daemon-http-policy',
          suggestedAction: 'allow',
          suggestedDuration: 'session',
        })
        if (result.action === 'allow') {
          const expiresAt = durationToExpiresAt(result.duration)
          const decisionRule = result.rule && typeof result.rule === 'object' ? result.rule : suggestedRule
          runtimeRules.push({
            ...decisionRule,
            expiresAt,
          })
          rememberTemporaryHttpDecision({
            action: 'allow',
            rule: decisionRule,
            duration: result.duration || 'once',
            expiresAt,
            request: normalized,
            ruleId: result.ruleId || ruleIdFor(decisionRule),
          })
          recordNetworkDecision({
            host: normalized.host,
            method,
            path: normalized.path,
            allowed: true,
            reason: result.reason,
            alertId: result.alertId,
            ruleId: result.ruleId || ruleIdFor(decisionRule),
            suggestedRule: decisionRule,
            duration: result.duration || 'once',
            expiresAt: result.expiresAt || '',
          })
          return {
            action: 'allow',
            reason: result.reason,
            suggestedRule,
            duration: result.duration || 'once',
          }
        }
        recordNetworkDecision({
          host: normalized.host,
          method,
          path: normalized.path,
          allowed: false,
          reason: result.reason,
          alertId: result.alertId,
          suggestedRule,
          suggestedRuleId: ruleIdFor(suggestedRule),
        })
        return { action: 'deny', reason: result.reason, suggestedRule }
      } catch (error) {
        recordNetworkDecision({
          host: normalized.host,
          method,
          path: normalized.path,
          allowed: false,
          reason: 'guardd-policy-unavailable',
          error: error.message,
          suggestedRule,
          suggestedRuleId: ruleIdFor(suggestedRule),
        })
        if (network.nativePromptFallback === true && resolveAskUi() === 'native') {
          return await askHttpPolicyInNative(normalized, suggestedRule)
        }
        return { action: 'deny', reason: `guardd policy unavailable: ${error.message}`, suggestedRule }
      }
    }
    return await askForHttpRule()
  }

  const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405)
      res.end()
      return
    }
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', async () => {
      try {
        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
        const decision = await decide(payload)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify(decision))
      } catch (error) {
        res.writeHead(500, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ action: 'deny', reason: error.message }))
      }
    })
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  if (!address || typeof address === 'string') {
    throw new Error('failed to start policy decision server')
  }
  return {
    endpoint: `http://127.0.0.1:${address.port}/decision`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}

const startIronProxy = async () => {
  const ironProxy = resolveIronProxy()
  const httpPort = await getFreeLoopbackPort()
  const socksPort = await getFreeLoopbackPort()
  const caDir = path.join(process.env.GUARD_RUN_DIR, 'iron-proxy-ca')
  const configPath = path.join(process.env.GUARD_RUN_DIR, 'iron-proxy.yaml')
  let caCert = path.join(caDir, 'ca.crt')
  let caKey = path.join(caDir, 'ca.key')
  let caSource = 'iron-proxy'

  try {
    const guarddCA = await resolveGuarddIronProxyCA()
    if (guarddCA) {
      fs.mkdirSync(caDir, { recursive: true })
      fs.copyFileSync(guarddCA.caCert, caCert)
      fs.chmodSync(caCert, 0o644)
      caKey = guarddCA.caKey
      caSource = guarddCA.source
    } else {
      generateIronProxyCA(ironProxy, caDir)
    }
  } catch (error) {
    recordGuardEvent('tls.cert_cache_warm_failed', {
      backend: 'iron-proxy',
      reason: error.message,
      fallback: 'iron-proxy-generate-ca',
      globalTrustManaged: false,
    })
    generateIronProxyCA(ironProxy, caDir)
  }

  let policyServer = null
  if (askNetworkEnabled) {
    policyServer = await startPolicyDecisionServer()
    cleanups.push(() => policyServer.close())
  }

  fs.writeFileSync(
    configPath,
    buildIronProxyConfig({
      httpPort,
      socksPort,
      caCert,
      caKey,
      policyEndpoint: policyServer?.endpoint || '',
    }),
  )

  const child = spawn(ironProxy.command, [...ironProxy.argsPrefix, '-config', configPath], {
    cwd: ironProxy.cwd,
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  let stderrBuffer = ''
  child.stderr.on('data', (chunk) => {
    const text = chunk.toString('utf8')
    stderrBuffer += text
    const lines = stderrBuffer.split(/\r?\n/)
    stderrBuffer = lines.pop() || ''
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      recordIronProxyAudit(trimmed)
      if (shouldPrintIronProxyLog(trimmed)) {
        process.stderr.write(`${line}\n`)
      }
    }
  })
  child.stderr.on('close', () => {
    const trimmed = stderrBuffer.trim()
    if (trimmed) {
      recordIronProxyAudit(trimmed)
      if (shouldPrintIronProxyLog(trimmed)) {
        process.stderr.write(`${stderrBuffer}\n`)
      }
    }
    stderrBuffer = ''
  })
  cleanups.push(
    () =>
      new Promise((resolve) => {
        let exited = false
        child.once('exit', () => {
          exited = true
          resolve()
        })
        child.kill('SIGTERM')
        setTimeout(() => {
          if (!exited) child.kill('SIGKILL')
          resolve()
        }, 2000).unref()
      }),
  )
  await waitForLoopbackPort(httpPort)
  return { httpPort, socksPort, caCert, caSource }
}

const extractDeniedLines = (text) =>
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) =>
      /deny|denied|operation not permitted|not allowed|blocked|sandbox/i.test(line),
    )

const writeDiscoveryReport = ({ code, signal, command }) => {
  if (!discoveryReportPath) return
  const stderr = discoveryStderr.join('')
  const stdout = discoveryStdout.join('')
  const deniedLines = [...new Set(extractDeniedLines(`${stderr}\n${stdout}`))]
  const networkEvents = networkLogPath && fs.existsSync(networkLogPath)
    ? fs
        .readFileSync(networkLogPath, 'utf8')
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => {
          try {
            return JSON.parse(line)
          } catch {
            return null
          }
        })
        .filter(Boolean)
    : []
  const allowedHosts = [
    ...new Set(
      networkEvents
        .filter((event) => event.allowed)
        .map((event) => event.host)
        .filter(Boolean),
    ),
  ].sort()
  const deniedHosts = [
    ...new Set(
      networkEvents
        .filter((event) => !event.allowed)
        .map((event) => event.host)
        .filter(Boolean),
    ),
  ].sort()

  const suggestedPatch = {
    network: {
      allowedDomains: allowedHosts,
      deniedDomains: deniedHosts,
    },
  }

  const lines = [
    '# Guard Discovery Report',
    '',
    `profile: ${process.env.GUARD_DISCOVERY_PROFILE || '-'}`,
    `config: ${process.env.GUARD_DISCOVERY_CONFIG || '-'}`,
    `command: ${command.join(' ')}`,
    `exit: ${signal || (code ?? 0)}`,
    `networkLog: ${networkLogPath || '-'}`,
    '',
    '## Network Hosts',
    '',
    `allowed: ${allowedHosts.length > 0 ? allowedHosts.join(' ') : '-'}`,
    `denied: ${deniedHosts.length > 0 ? deniedHosts.join(' ') : '-'}`,
    '',
    '## Denied Output Lines',
    '',
    ...(deniedLines.length > 0 ? deniedLines.map((line) => `- ${line}`) : ['- none captured']),
    '',
    '## Suggested Patch Seed',
    '',
    '```json',
    JSON.stringify(suggestedPatch, null, 2),
    '```',
    '',
  ]

  try {
    fs.mkdirSync(path.dirname(discoveryReportPath), { recursive: true })
    fs.writeFileSync(discoveryReportPath, `${lines.join('\n')}\n`)
    console.error(`guard discover: wrote ${discoveryReportPath}`)
  } catch (error) {
    console.error(`guard discover: failed to write report: ${error.message}`)
  }
}

const materializeHomeLinks = (links = []) => {
  for (const link of links) {
    if (typeof link?.source !== 'string' || typeof link?.target !== 'string') {
      continue
    }
    if (!link.source || !link.target || path.isAbsolute(link.target)) {
      continue
    }

    const target = path.resolve(process.env.GUARD_HOME_DIR, link.target)
    const homeRoot = path.resolve(process.env.GUARD_HOME_DIR)
    if (target !== homeRoot && !target.startsWith(`${homeRoot}${path.sep}`)) {
      continue
    }

    fs.mkdirSync(path.dirname(target), { recursive: true })
    try {
      if (fs.lstatSync(target).isSymbolicLink()) {
        fs.unlinkSync(target)
      } else {
        fs.rmSync(target, { force: true, recursive: true })
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    fs.symlinkSync(link.source, target)
  }
}

const buildSupplyChainEnv = (supplyChain = {}) => {
  if (supplyChain.installHardening !== true) return []
  return [
    'GUARD_SUPPLY_CHAIN_HARDENING=1',
    'NPM_CONFIG_IGNORE_SCRIPTS=true',
    'npm_config_ignore_scripts=true',
    'YARN_ENABLE_SCRIPTS=false',
    'PNPM_IGNORE_SCRIPTS=true',
    'PIP_DISABLE_PIP_VERSION_CHECK=1',
    'PIP_NO_INPUT=1',
    'UV_NO_PROGRESS=1',
  ]
}

const main = async () => {
  let httpProxyPort
  let socksProxyPort
  let nodeOptions = process.env.NODE_OPTIONS || ''

  let ironProxyCA = ''

  if (runtimeBackend === 'bubblewrap') {
    assertLinuxBubblewrapSupported(cfg, { proxyEnabled })
  }

  if (proxyEnabled && networkBackend === 'iron-proxy') {
    const ironProxy = await startIronProxy()
    httpProxyPort = ironProxy.httpPort
    socksProxyPort = ironProxy.socksPort
    ironProxyCA = ironProxy.caCert
    recordGuardEvent('proxy.started', {
      backend: 'iron-proxy',
      httpProxyPort,
      socksProxyPort,
      caCert: ironProxyCA,
      caSource: ironProxy.caSource,
      tlsInspection: {
        enabled: tlsInspectionEnabled,
        mode: tlsInspection.mode || (tlsInspectionEnabled ? 'ephemeral-run-ca' : 'off'),
        caScope: tlsInspectionEnabled ? 'guarded-process-env' : 'none',
      },
    })
  } else if (proxyEnabled) {
    const filter = createDomainFilter(network, {
      ask: askNetworkEnabled ? askNetworkAccess : undefined,
      onDecision: recordNetworkDecision,
    })
    const httpProxy = await startHttpProxy({ filter, onTraffic: recordNetworkFlow })
    const socksProxy = await startSocksProxy({ filter, onTraffic: recordNetworkFlow })
    cleanups.push(() => httpProxy.close())
    cleanups.push(() => socksProxy.close())
    httpProxyPort = httpProxy.port
    socksProxyPort = socksProxy.port
    recordGuardEvent('proxy.started', {
      backend: 'guard',
      httpProxyPort,
      socksProxyPort,
    })

  }

  if (proxyEnabled) {
    const nodeFetchProxyPreloadSource = fileURLToPath(
      new URL('./guard-node-fetch-proxy.mjs', import.meta.url),
    )
    const nodeFetchProxyPreload = `${process.env.GUARD_RUN_DIR}/node-fetch-proxy.mjs`
    fs.copyFileSync(nodeFetchProxyPreloadSource, nodeFetchProxyPreload)
    nodeOptions = `--import=${nodeFetchProxyPreload} ${nodeOptions}`.trim()
  }

  materializeHomeLinks(cfg.homeLinks)
  const resolvedRawTcpRules = await resolveAllowedRawTcp(network.allowedRawTcp)

  fs.writeFileSync(
    guardProfilePath,
    generateProfile(cfg, {
      cwd: process.env.GUARD_CWD || process.cwd(),
      projectDir: process.env.GUARD_PROJECT_DIR,
      guardRunDir: process.env.GUARD_RUN_DIR,
      executablePaths,
      httpProxyPort,
      socksProxyPort,
      resolvedRawTcpRules,
      logTag: runSandboxLogTag,
    }),
  )
  recordGuardEvent('sandbox.profile_written', {
    profilePath: guardProfilePath,
    networkMode: networkBackend,
    proxyEnabled,
    sandboxLogTag: runSandboxLogTag,
    denialLogEnabled: sandboxDenialLogEnabled,
  })

  if (sandboxDenialLogEnabled) {
    const stream = startSandboxDenialStream({
      tag: runSandboxLogTag,
      onDenial: (denial) => {
        if (shouldRecordSandboxDenial(denial)) {
          recordGuardEvent('sandbox.denial', denial)
        }
      },
      onError: (message) => recordGuardEvent('sandbox.denial_stream.error', {
        backend: 'sandbox-exec',
        source: 'macos-unified-log',
        message,
      }),
    })
    cleanups.push(() => stream.stop())
    if (sandboxDenialLogStartupMs > 0) {
      await delay(sandboxDenialLogStartupMs)
    }
  }

  const proxyEnv = proxyEnabled
    ? buildProxyEnv({ httpPort: httpProxyPort, socksPort: socksProxyPort })
    : []
  const caEnv = ironProxyCA && tlsInspectionEnabled
    ? [
        `NODE_EXTRA_CA_CERTS=${ironProxyCA}`,
        `SSL_CERT_FILE=${ironProxyCA}`,
        `REQUESTS_CA_BUNDLE=${ironProxyCA}`,
        `CURL_CA_BUNDLE=${ironProxyCA}`,
        `GIT_SSL_CAINFO=${ironProxyCA}`,
      ]
    : []
  const supplyChainEnv = buildSupplyChainEnv(cfg.supplyChain)
  const clearInheritedEnv =
    cfg.supplyChain?.installHardening === true &&
    cfg.supplyChain?.sanitizeEnvironment !== false

  const stdio = discoveryReportPath ? ['inherit', 'pipe', 'pipe'] : 'inherit'
  const runnerEnv = [
    `HOME=${process.env.GUARD_HOME_DIR}`,
    `TMPDIR=${process.env.GUARD_TMP_DIR}`,
    `TMP=${process.env.GUARD_TMP_DIR}`,
    `TEMP=${process.env.GUARD_TMP_DIR}`,
    `PATH=${process.env.GUARD_INNER_PATH}`,
    `NODE_OPTIONS=${nodeOptions}`,
    `XDG_CACHE_HOME=${process.env.GUARD_HOME_DIR}/.cache`,
    'NPM_CONFIG_USERCONFIG=/dev/null',
    `NPM_CONFIG_CACHE=${process.env.GUARD_TMP_DIR}/npm-cache`,
    `npm_config_cache=${process.env.GUARD_TMP_DIR}/npm-cache`,
    `PNPM_HOME=${process.env.GUARD_HOME_DIR}/.pnpm`,
    `PNPM_STORE_DIR=${process.env.GUARD_TMP_DIR}/pnpm-store`,
    `YARN_CACHE_FOLDER=${process.env.GUARD_TMP_DIR}/yarn-cache`,
    'NUXT_TELEMETRY_DISABLED=1',
    `DOCKER_HOST=unix://${process.env.GUARD_REAL_HOME}/.docker/run/docker.sock`,
    `DOCKER_CONFIG=${process.env.GUARD_DOCKER_CONFIG}`,
    'GUARD_ACTIVE=1',
    `GUARD_REAL_HOME=${process.env.GUARD_REAL_HOME}`,
    `GUARD_RUN_DIR=${process.env.GUARD_RUN_DIR}`,
    `GUARD_PROJECT_DIR=${process.env.GUARD_PROJECT_DIR}`,
    `GUARD_CWD=${process.env.GUARD_CWD}`,
    ...proxyEnv,
    ...caEnv,
    ...supplyChainEnv,
  ]
  const childCommand = runtimeBackend === 'bubblewrap' ? 'bwrap' : '/usr/bin/sandbox-exec'
  const childArgs = runtimeBackend === 'bubblewrap'
    ? buildBubblewrapArgs({
        cfg,
        commandArgs,
        env: runnerEnv,
        cwd: process.env.GUARD_CWD || process.cwd(),
        executablePaths,
        clearEnv: clearInheritedEnv,
      })
    : [
        '-f',
        guardProfilePath,
        '/usr/bin/env',
        ...(clearInheritedEnv ? ['-i'] : []),
        ...runnerEnv,
        ...commandArgs,
      ]
  const child = spawn(
    childCommand,
    childArgs,
    {
      cwd: process.env.GUARD_RUNTIME_CWD || process.cwd(),
      stdio,
    },
  )
  recordGuardEvent('process.started', {
    pid: child.pid || null,
  })

  if (discoveryReportPath) {
    child.stdout.on('data', (chunk) => {
      discoveryStdout.push(chunk.toString('utf8'))
      process.stdout.write(chunk)
    })
    child.stderr.on('data', (chunk) => {
      discoveryStderr.push(chunk.toString('utf8'))
      process.stderr.write(chunk)
    })
  }

  const forwardSignal = (signal) => {
    child.kill(signal)
  }

  process.on('SIGINT', forwardSignal)
  process.on('SIGTERM', forwardSignal)

  child.on('exit', async (code, signal) => {
    recordGuardEvent('process.exited', {
      code,
      signal,
    })
    writeDiscoveryReport({ code, signal, command: commandArgs })
    await closeAll()
    if (signal) {
      process.kill(process.pid, signal)
      return
    }
    process.exit(code ?? 1)
  })

  child.on('error', async (error) => {
    console.error(`guard: failed to launch sandboxed command: ${error.message}`)
    await closeAll()
    process.exit(1)
  })
}

main().catch(async (error) => {
  console.error(`guard: ${error instanceof Error ? error.message : String(error)}`)
  await closeAll()
  process.exit(1)
})
