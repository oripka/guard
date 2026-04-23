#!/usr/bin/env node

import fs from 'node:fs'
import { spawn } from 'node:child_process'
import path from 'node:path'
import readline from 'node:readline/promises'
import { fileURLToPath } from 'node:url'

import { startHttpProxy, startSocksProxy, createDomainFilter, buildProxyEnv } from './guard-network.mjs'
import { generateProfile } from './guard-manager.mjs'

const [, , runtimeConfigPath, guardProfilePath, ...commandArgs] = process.argv

if (!runtimeConfigPath || !guardProfilePath || commandArgs.length === 0) {
  console.error(
    'usage: guard-runner.mjs <runtime-config.json> <profile.sb> <command> [args...]',
  )
  process.exit(2)
}

const cfg = JSON.parse(fs.readFileSync(runtimeConfigPath, 'utf8'))
const network = cfg.network || {}
const askNetworkEnabled = network.ask === true
const proxyEnabled =
  !cfg.networkUnrestricted &&
  (askNetworkEnabled ||
    (Array.isArray(network.allowedDomains) &&
      network.allowedDomains.length > 0))

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

const main = async () => {
  let httpProxyPort
  let socksProxyPort
  let nodeOptions = process.env.NODE_OPTIONS || ''

  if (proxyEnabled) {
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

    const nodeFetchProxyPreloadSource = fileURLToPath(new URL(
      './guard-node-fetch-proxy.mjs',
      import.meta.url,
    ))
    const nodeFetchProxyPreload = `${process.env.GUARD_RUN_DIR}/node-fetch-proxy.mjs`
    fs.copyFileSync(nodeFetchProxyPreloadSource, nodeFetchProxyPreload)
    nodeOptions = `--import=${nodeFetchProxyPreload} ${nodeOptions}`.trim()
  }

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
