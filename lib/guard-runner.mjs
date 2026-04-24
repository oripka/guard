#!/usr/bin/env node

import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import { spawn, spawnSync } from 'node:child_process'
import path from 'node:path'
import readline from 'node:readline/promises'
import { fileURLToPath } from 'node:url'

import { startHttpProxy, startSocksProxy, createDomainFilter, buildProxyEnv } from './guard-network.mjs'
import { generateProfile } from './guard-manager.mjs'

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
const networkBackend = network.backend || 'guard'
const proxyEnabled =
  !cfg.networkUnrestricted &&
  (askNetworkEnabled ||
    (Array.isArray(network.allowedDomains) &&
      network.allowedDomains.length > 0) ||
    (Array.isArray(network.httpRules) && network.httpRules.length > 0))

const cleanups = []
const networkLogPath = process.env.GUARD_NETWORK_LOG || ''
const discoveryReportPath = process.env.GUARD_DISCOVERY_REPORT || ''
const discoveryStderr = []
const discoveryStdout = []

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

const recordNetworkDecision = (event) => {
  appendJsonLine(networkLogPath, {
    at: new Date().toISOString(),
    profile: process.env.GUARD_DISCOVERY_PROFILE || '',
    ...event,
  })
}

const formatHostPort = (host, port) =>
  Number.isInteger(port) && port > 0 ? `${host}:${port}` : host

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
    `Allow network access to ${target} for this guard run?`,
  )
  const script = [
    `display dialog "${message}"`,
    'buttons {"Deny", "Allow"}',
    'default button "Deny"',
    'cancel button "Deny"',
    'with title "guard network access"',
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
      resolve(code === 0 && /button returned:Allow/.test(stdout))
    })
  })
}

const askNetworkAccessNow = async (host, port) => {
  const target = formatHostPort(host, port)
  if (!(process.stdin.isTTY && process.stderr.isTTY)) {
    console.error(`guard: blocked network access to ${target}; --ask-network requires an interactive terminal`)
    return false
  }

  if (resolveAskUi() === 'dialog') {
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

const buildIronProxyConfig = ({ httpPort, socksPort, caCert, caKey, policyEndpoint }) => {
  const allowedDomains = Array.isArray(network.allowedDomains) ? network.allowedDomains : []
  const httpRules = Array.isArray(network.httpRules) ? network.httpRules : []
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
    if (allowedDomains.length > 0 || httpRules.length > 0) {
      lines.push('      rules:')
      for (const host of allowedDomains) {
        appendRuleYaml(lines, { host }, 8)
      }
      for (const rule of httpRules) {
        appendRuleYaml(lines, rule, 8)
      }
    }
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

  lines.push('metrics:', '  listen: "off"', 'log:', '  level: "info"')
  return `${lines.join('\n')}\n`
}

const resolveIronProxy = () => {
  if (process.env.GUARD_IRON_PROXY_BIN) {
    return { command: process.env.GUARD_IRON_PROXY_BIN, argsPrefix: [], cwd: process.cwd() }
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

const ruleMatchesRequest = (rule, request) => {
  const normalized = normalizeRule(rule)
  if (normalized.host && normalized.host !== request.host) return false
  if (normalized.methods.length > 0 && !normalized.methods.includes(request.method)) return false
  if (normalized.paths.length > 0 && !normalized.paths.some((pattern) => pathMatches(pattern, request.path))) return false
  return true
}

const wildcardPathFor = (requestPath) => {
  const parts = String(requestPath || '/').split('/').filter(Boolean)
  if (parts.length <= 1) return '/*'
  return `/${parts.slice(0, -1).join('/')}/*`
}

const askHttpPolicyInTerminal = async (request, suggestedRule) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr })
  try {
    const reply = await rl.question(
      `guard: allow ${request.method} ${request.host}${request.path}? [e]xact/[w]ildcard/[h]ost/[d]eny `,
    )
    const choice = reply.trim().toLowerCase()
    if (choice === 'h' || choice === 'host') {
      return { action: 'allow', rule: { host: request.host } }
    }
    if (choice === 'w' || choice === 'wildcard') {
      return { action: 'allow', rule: suggestedRule }
    }
    if (choice === 'e' || choice === 'exact' || choice === 'y' || choice === 'yes') {
      return {
        action: 'allow',
        rule: { host: request.host, methods: [request.method], paths: [request.path] },
      }
    }
    return { action: 'deny' }
  } finally {
    rl.close()
  }
}

const askHttpPolicyInDialog = async (request, suggestedRule) => {
  const message = escapeAppleScriptString(
    `Allow ${request.method} ${request.host}${request.path}?\n\nExact allows only this path. Wildcard allows ${suggestedRule.paths[0]}.`,
  )
  const script = [
    `display dialog "${message}"`,
    'buttons {"Deny", "Allow Exact", "Allow Wildcard"}',
    'default button "Deny"',
    'cancel button "Deny"',
    'with title "guard egress policy"',
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
      } else if (/button returned:Allow Wildcard/.test(stdout)) {
        resolve({ action: 'allow', rule: suggestedRule })
      } else if (/button returned:Allow Exact/.test(stdout)) {
        resolve({
          action: 'allow',
          rule: { host: request.host, methods: [request.method], paths: [request.path] },
        })
      } else {
        resolve({ action: 'deny' })
      }
    })
  })
}

const startPolicyDecisionServer = async () => {
  const runtimeRules = []
  const configuredRules = [
    ...(Array.isArray(network.allowedDomains) ? network.allowedDomains.map((host) => ({ host })) : []),
    ...(Array.isArray(network.httpRules) ? network.httpRules : []),
  ]
  let queue = Promise.resolve()

  const decide = async (request) => {
    const method = String(request.method || '').toUpperCase()
    const normalized = {
      ...request,
      method,
      host: String(request.host || '').toLowerCase(),
      path: request.path || '/',
    }

    if ([...configuredRules, ...runtimeRules].some((rule) => ruleMatchesRequest(rule, normalized))) {
      return { action: 'allow', reason: 'matched-rule' }
    }

    const suggestedRule = {
      host: normalized.host,
      methods: [method],
      paths: [wildcardPathFor(normalized.path)],
    }
    if (!(process.stdin.isTTY && process.stderr.isTTY)) {
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: false,
        reason: 'interactive-policy-noninteractive',
        suggestedRule,
      })
      return {
        action: 'deny',
        reason: '--ask-network requires an interactive terminal',
        suggestedRule,
      }
    }
    const ask = () =>
      resolveAskUi() === 'dialog'
        ? askHttpPolicyInDialog(normalized, suggestedRule)
        : askHttpPolicyInTerminal(normalized, suggestedRule)
    const decision = queue.then(ask, ask)
    queue = decision.catch(() => {})
    const result = await decision
    if (result.action === 'allow' && result.rule) {
      runtimeRules.push(result.rule)
      recordNetworkDecision({
        host: normalized.host,
        method,
        path: normalized.path,
        allowed: true,
        reason: 'interactive-policy',
        suggestedRule: result.rule,
      })
      return {
        action: 'allow',
        reason: 'interactive-policy',
        suggestedRule: result.rule,
      }
    }
    recordNetworkDecision({
      host: normalized.host,
      method,
      path: normalized.path,
      allowed: false,
      reason: 'interactive-policy',
      suggestedRule,
    })
    return { action: 'deny', reason: 'interactive-policy', suggestedRule }
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
  const caCert = path.join(caDir, 'ca.crt')
  const caKey = path.join(caDir, 'ca.key')

  generateIronProxyCA(ironProxy, caDir)

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
  child.stderr.on('data', (chunk) => process.stderr.write(chunk))
  cleanups.push(
    () =>
      new Promise((resolve) => {
        child.once('exit', resolve)
        child.kill('SIGTERM')
        setTimeout(() => {
          if (!child.killed) child.kill('SIGKILL')
          resolve()
        }, 2000).unref()
      }),
  )
  await waitForLoopbackPort(httpPort)
  return { httpPort, socksPort, caCert }
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

const main = async () => {
  let httpProxyPort
  let socksProxyPort
  let nodeOptions = process.env.NODE_OPTIONS || ''

  let ironProxyCA = ''

  if (proxyEnabled && networkBackend === 'iron-proxy') {
    const ironProxy = await startIronProxy()
    httpProxyPort = ironProxy.httpPort
    socksProxyPort = ironProxy.socksPort
    ironProxyCA = ironProxy.caCert
  } else if (proxyEnabled) {
    const filter = createDomainFilter(network, {
      ask: askNetworkEnabled ? askNetworkAccess : undefined,
      onDecision: recordNetworkDecision,
    })
    const httpProxy = await startHttpProxy({ filter })
    const socksProxy = await startSocksProxy({ filter })
    cleanups.push(() => httpProxy.close())
    cleanups.push(() => socksProxy.close())
    httpProxyPort = httpProxy.port
    socksProxyPort = socksProxy.port

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

  fs.writeFileSync(
    guardProfilePath,
    generateProfile(cfg, {
      cwd: process.env.GUARD_CWD || process.cwd(),
      projectDir: process.env.GUARD_PROJECT_DIR,
      guardRunDir: process.env.GUARD_RUN_DIR,
      httpProxyPort,
      socksProxyPort,
    }),
  )

  const proxyEnv = proxyEnabled
    ? buildProxyEnv({ httpPort: httpProxyPort, socksPort: socksProxyPort })
    : []
  const caEnv = ironProxyCA
    ? [
        `NODE_EXTRA_CA_CERTS=${ironProxyCA}`,
        `SSL_CERT_FILE=${ironProxyCA}`,
        `REQUESTS_CA_BUNDLE=${ironProxyCA}`,
        `CURL_CA_BUNDLE=${ironProxyCA}`,
        `GIT_SSL_CAINFO=${ironProxyCA}`,
      ]
    : []

  const stdio = discoveryReportPath ? ['inherit', 'pipe', 'pipe'] : 'inherit'
  const child = spawn(
    '/usr/bin/sandbox-exec',
    [
      '-f',
      guardProfilePath,
      '/usr/bin/env',
      `HOME=${process.env.GUARD_HOME_DIR}`,
      `TMPDIR=${process.env.GUARD_TMP_DIR}`,
      `TMP=${process.env.GUARD_TMP_DIR}`,
      `TEMP=${process.env.GUARD_TMP_DIR}`,
      `PATH=${process.env.GUARD_INNER_PATH}`,
      `NODE_OPTIONS=${nodeOptions}`,
      `XDG_CACHE_HOME=${process.env.GUARD_HOME_DIR}/.cache`,
      'NPM_CONFIG_USERCONFIG=/dev/null',
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
      ...commandArgs,
    ],
    {
      cwd: process.env.GUARD_RUNTIME_CWD || process.cwd(),
      stdio,
    },
  )

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
