import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline/promises'
import zlib from 'node:zlib'
import { spawn, spawnSync } from 'node:child_process'
import {
  MUTABLE_PROFILE_ARRAY_FIELDS,
  loadProfileConfig,
  mutateArrayRuleConfig,
  mutateHttpRuleConfig,
  mutateRawTcpRuleConfig,
  mutateTlsConfig,
  readJsonFile,
  stableJson as stableProfileJson,
  writeJsonFile,
} from './guard-policy.mjs'

const SHIM_TOOL_NAMES = new Set([
  'node',
  'pnpm',
  'npm',
  'python',
  'python3',
  'pip',
  'pip3',
  'deno',
  'npx',
  'corepack',
  'guard-shim',
])

const RESOLVABLE_SHIM_TOOLS = ['node', 'pnpm', 'npm', 'python', 'python3', 'pip', 'pip3']

const DISABLED_TOOLS = new Set(['npx', 'corepack', 'deno'])

const FAST_VERSION_PROBE_TOOLS = new Set(['node', 'pnpm', 'npm'])
const VERSION_PROBE_FLAGS = new Set(['--version', '-v'])

const DENIED_DOMAIN_PRESETS = {
  telemetry: [
    '*.app-measurement.com',
    '*.doubleclick.net',
    '*.google-analytics.com',
    '*.googletagmanager.com',
    '*.segment.io',
    '*.sentry.io',
  ],
  updates: [
    '*.delivery.mp.microsoft.com',
    '*.officecdn.microsoft.com',
    '*.update.microsoft.com',
    'officecdn.microsoft.com',
  ],
  'microsoft-telemetry': [
    '*.aria.microsoft.com',
    '*.events.data.microsoft.com',
    'browser.pipe.aria.microsoft.com',
    'vortex.data.microsoft.com',
  ],
  'webex-telemetry': [
    '*.analytics.webex.com',
    '*.metrics.webex.com',
  ],
  'zoom-telemetry': [
    '*.events.zoom.us',
    '*.logfiles.zoom.us',
    'events.zoom.us',
    'logfiles.zoom.us',
  ],
}

const TOOL_SPECS = {
  node: {
    overrideEnv: 'GUARD_REAL_NODE',
    bypassEnv: 'NODE_GUARD_BYPASS',
    lookup: ['node'],
    fallbacks: ['/opt/homebrew/bin/node', '/usr/local/bin/node'],
  },
  pnpm: {
    overrideEnv: 'GUARD_REAL_PNPM',
    bypassEnv: 'PNPM_GUARD_BYPASS',
    lookup: ['pnpm'],
    fallbacks: ['/opt/homebrew/bin/pnpm', '/usr/local/bin/pnpm'],
  },
  npm: {
    overrideEnv: 'GUARD_REAL_NPM',
    bypassEnv: 'NPM_GUARD_BYPASS',
    lookup: ['npm'],
    fallbacks: ['/opt/homebrew/bin/npm', '/usr/local/bin/npm'],
  },
  python: {
    overrideEnv: 'GUARD_REAL_PYTHON',
    bypassEnv: 'PYTHON_GUARD_BYPASS',
    lookup: ['python3', 'python'],
    fallbacks: ['/opt/homebrew/bin/python3', '/usr/bin/python3'],
  },
  python3: {
    overrideEnv: 'GUARD_REAL_PYTHON3',
    bypassEnv: 'PYTHON3_GUARD_BYPASS',
    lookup: ['python3'],
    fallbacks: ['/opt/homebrew/bin/python3', '/usr/bin/python3'],
  },
  pip: {
    overrideEnv: 'GUARD_REAL_PIP',
    bypassEnv: 'PIP_GUARD_BYPASS',
    lookup: ['pip3', 'pip'],
    fallbacks: ['/opt/homebrew/bin/pip3', '/usr/bin/pip3'],
  },
  pip3: {
    overrideEnv: 'GUARD_REAL_PIP3',
    bypassEnv: 'PIP3_GUARD_BYPASS',
    lookup: ['pip3'],
    fallbacks: ['/opt/homebrew/bin/pip3', '/usr/bin/pip3'],
  },
}

const versionProbeToolName = (command) => {
  const tool = path.basename(String(command || ''))
  if (FAST_VERSION_PROBE_TOOLS.has(tool)) return tool
  if (tool === 'pnpm.cjs') return 'pnpm'
  if (tool === 'npm-cli.js') return 'npm'
  return ''
}

const isFastVersionProbe = (args) => {
  if (!Array.isArray(args) || args.length !== 2) return false
  const tool = versionProbeToolName(args[0])
  return FAST_VERSION_PROBE_TOOLS.has(tool) && VERSION_PROBE_FLAGS.has(args[1])
}

const reduceNetworkForVersionProbe = (cfg) => ({
  ...cfg,
  networkUnrestricted: false,
  network: {
    ...(cfg.network || {}),
    allowedDomains: [],
    deniedDomains: [],
    deniedDomainPresets: [],
    ask: false,
    discovery: false,
    allowLocalBinding: false,
    allowLoopbackConnections: false,
    allowLoopbackHighPorts: false,
    allowLoopbackPorts: [],
  },
})

const normalizeListeningHighPortProcesses = (value) => {
  if (value === true) return null
  if (!Array.isArray(value)) return []
  return value
    .filter((entry) => typeof entry === 'string' && entry.trim())
    .map((entry) => entry.trim())
}

const isLoopbackListeningHighPortsEnabled = (value) =>
  value === true || normalizeListeningHighPortProcesses(value).length > 0

const parseListeningLoopbackHighPortEntries = (output, processNames = null) => {
  const allowedProcesses = Array.isArray(processNames) ? new Set(processNames) : null
  const ports = new Set()
  for (const line of String(output || '').split('\n')) {
    const match = line.match(/^(\S+)\s+.*\sTCP\s+(.+):(\d+)\s+\(LISTEN\)$/)
    if (!match) continue
    const command = match[1]
    if (allowedProcesses && !allowedProcesses.has(command)) continue

    const host = match[2].trim()
    if (!['127.0.0.1', 'localhost', '[::1]', '::1'].includes(host)) continue

    const port = Number(match[3])
    if (Number.isInteger(port) && port >= 49152 && port <= 65535) {
      ports.add(port)
    }
  }
  return [...ports].sort((left, right) => left - right)
}

const collectListeningLoopbackHighPorts = (processNames = null) => {
  const result = spawnSync('/usr/sbin/lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], {
    encoding: 'utf8',
  })
  if (result.error || result.status !== 0) return []
  return parseListeningLoopbackHighPortEntries(result.stdout, processNames)
}

const addLoopbackListeningHighPorts = (cfg) => {
  const netCfg = cfg.network || {}
  const processNames = normalizeListeningHighPortProcesses(
    netCfg.allowLoopbackListeningHighPorts,
  )
  if (!isLoopbackListeningHighPortsEnabled(netCfg.allowLoopbackListeningHighPorts)) {
    return cfg
  }

  const ports = collectListeningLoopbackHighPorts(processNames)
  if (ports.length === 0) return cfg

  return {
    ...cfg,
    network: {
      ...netCfg,
      allowLoopbackPorts: [
        ...new Set([
          ...(Array.isArray(netCfg.allowLoopbackPorts) ? netCfg.allowLoopbackPorts : []),
          ...ports,
        ]),
      ],
    },
  }
}

const usage = `Usage:
  guard [--profile NAME] [--ask-network] [--deep-egress] <command> [args...]
  guard [--profile NAME] [--ask-network] [--deep-egress] -- <command> [args...]
  guard [--profile NAME] [--ask-network] [--deep-egress]
  guard help
  guard run <webex|teams|zoom> [args...]
  guard doctor [tool] [--json]
  guard audit [--json]
  guard settings [--json]
  guard tls status [--json]
  guard app-summary --profile NAME [--json]
  guard daemon [guardd options...]
  guard ui [--dir DIR]
  guard monitor-log [--json] [--limit N] [PATH]
  guard profile add FIELD VALUE [--json]
  guard profile remove FIELD VALUE [--json]
  guard profile add-http-rule (--host HOST|--cidr CIDR) [--method METHOD] [--path PATH] [--json]
  guard profile remove-http-rule (--host HOST|--cidr CIDR) [--method METHOD] [--path PATH] [--json]
  guard profile add-raw-tcp (--host HOST [--resolve-at-launch]|--ip IP) --port PORT [--reason TEXT] [--json]
  guard profile remove-raw-tcp (--host HOST [--resolve-at-launch]|--ip IP) --port PORT [--reason TEXT] [--json]
  guard profile tls <enable|disable|status> [--json]
  guard profile doctor [--json]
  guard install-monitor [--dir DIR] [--force]
  guard install-app <webex|teams|zoom> [--dir DIR] [--force]
  guard install-app all [--dir DIR] [--force]
  guard install-apps [--dir DIR] [--force]
  guard discover [--profile NAME] [--report PATH] -- <command> [args...]
  guard diff-profile OLD NEW [--json]
  guard network-log PATH [--json]
  guard list profiles [--json]
  guard list templates [--json]
  guard list domain-presets [--json]
  guard setup [--bin-dir DIR] [--code-root DIR] [--shims|--no-shims] [--force] [--yes]
  guard install [--bin-dir DIR] [--code-root DIR] [--no-shims] [--force]
  guard init [template] [--force]

Runs a command through the native guard runtime using the nearest
.guard/<profile>.json found by walking upward from the current directory,
or a built-in profiles/<profile>.json shipped with this repo.

With no command, prints the resolved guard policy for the current directory.

Examples:
  guard
  guard pnpm run dev
  guard run webex
  guard run teams
  guard run zoom
  guard install-app webex
  guard doctor
  guard doctor pnpm --json
  guard audit
  guard settings
  guard tls status
  guard daemon --port 8765
  guard ui
  guard profile doctor
  guard help
  guard discover --profile teams -- /Applications/Microsoft\\ Teams.app/Contents/MacOS/MSTeams
  guard diff-profile zoom teams
  guard network-log /tmp/guard-network.jsonl
  guard monitor-log
  guard profile add network.allowedDomains registry.npmjs.org
  guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
  guard profile add-raw-tcp --host localhost --resolve-at-launch --port 8976 --reason "local OAuth callback"
  guard list profiles
  guard list templates
  guard list domain-presets
  guard setup
  guard install
  guard init
  guard install-apps --force
`

const emit = (stream, text = '') => stream.write(`${text}\n`)

const safeRealpath = (value) => {
  try {
    return fs.realpathSync(value)
  } catch {
    return path.resolve(value)
  }
}

const ensureExecutable = (target, label) => {
  try {
    fs.accessSync(target, fs.constants.X_OK)
  } catch {
    throw new Error(`${label} not executable at ${target}`)
  }
}

const spawnAndExit = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      ...options,
    })
    child.on('error', reject)
    child.on('exit', (code, signal) => resolve({ code, signal }))
  })

const exitLikeChild = async (command, args, options = {}) => {
  const { code, signal } = await spawnAndExit(command, args, options)
  if (signal) {
    process.kill(process.pid, signal)
    return
  }
  process.exit(code ?? 1)
}

const isInsideRoot = (cwd, root) => {
  const rel = path.relative(root, cwd)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

const findNearestProfile = (cwd, profile) => {
  let dir = cwd
  while (true) {
    const candidate = path.join(dir, '.guard', `${profile}.json`)
    if (fs.existsSync(candidate)) {
      return { config: candidate, projectDir: dir, source: 'project' }
    }
    if (dir === '/') break
    dir = path.dirname(dir)
  }
  return null
}

const findBuiltInProfile = (repoRoot, profile, cwd) => {
  const repoProfile = path.resolve(repoRoot, 'profiles', `${profile}.json`)
  if (!fs.existsSync(repoProfile)) return null
  return {
    config: repoProfile,
    projectDir: profile === 'guard' ? '' : cwd,
    source: 'builtin',
  }
}

const getNetworkMode = (cfg) => {
  const network = cfg.network || {}
  const allowedDomains = Array.isArray(network.allowedDomains)
    ? network.allowedDomains
    : []
  const httpRules = Array.isArray(network.httpRules) ? network.httpRules : []
  const allowedRawTcp = Array.isArray(network.allowedRawTcp)
    ? network.allowedRawTcp
    : []
  if (cfg.networkUnrestricted === true) return 'unrestricted'
  if (network.backend === 'iron-proxy' && network.ask === true) return 'iron-proxy+ask'
  if (network.backend === 'iron-proxy') return 'iron-proxy'
  if (network.ask === true && (allowedDomains.length > 0 || httpRules.length > 0)) {
    return 'allowlist+ask'
  }
  if (network.ask === true) return 'ask'
  if (allowedDomains.length > 0 || httpRules.length > 0 || allowedRawTcp.length > 0) {
    return 'allowlist'
  }
  return 'none'
}

const applyDeniedDomainPresets = (network = {}) => {
  const presets = Array.isArray(network.deniedDomainPresets)
    ? network.deniedDomainPresets
    : []
  if (presets.length === 0) return network

  const denied = Array.isArray(network.deniedDomains)
    ? [...network.deniedDomains]
    : []
  for (const preset of presets) {
    const entries = DENIED_DOMAIN_PRESETS[preset]
    if (!entries) continue
    for (const entry of entries) {
      if (!denied.includes(entry)) {
        denied.push(entry)
      }
    }
  }
  return {
    ...network,
    deniedDomains: denied,
  }
}

const getProfileLauncher = (profile) => {
  for (const [launcher, app] of Object.entries(APP_LAUNCHERS || {})) {
    if (app.profile === profile) return launcher
  }
  return null
}

const listBuiltInProfiles = (repoRoot) => {
  const profilesDir = path.resolve(repoRoot, 'profiles')
  if (!fs.existsSync(profilesDir)) return []
  return fs
    .readdirSync(profilesDir)
    .filter((name) => name.endsWith('.json'))
    .sort((left, right) => left.localeCompare(right))
    .map((filename) => {
      const name = path.basename(filename, '.json')
      const profilePath = path.join(profilesDir, filename)
      const cfg = JSON.parse(fs.readFileSync(profilePath, 'utf8'))
      const network = cfg.network || {}
      const allowedDomains = Array.isArray(network.allowedDomains)
        ? network.allowedDomains
        : []
      const appBundles = Array.isArray(cfg.filesystem?.allowRead)
        ? cfg.filesystem.allowRead.filter((entry) =>
            typeof entry === 'string' && entry.startsWith('/Applications/'),
          )
        : []
      return {
        name,
        path: profilePath,
        source: 'builtin',
        description: cfg.metadata?.description || '',
        risk: cfg.metadata?.risk || 'unknown',
        status: cfg.metadata?.status || 'unknown',
        network: getNetworkMode(cfg),
        allowedDomainsCount: allowedDomains.length,
        appBundles,
        appBundle: cfg.metadata?.appBundle || appBundles[0] || null,
        launcher: cfg.metadata?.launcher || getProfileLauncher(name),
      }
    })
}

const listProjectTemplates = (repoRoot) => {
  const templatesDir = path.resolve(repoRoot, 'templates')
  if (!fs.existsSync(templatesDir)) return []
  return fs
    .readdirSync(templatesDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name !== 'imports')
    .map((entry) => {
      const templatePath = path.join(templatesDir, entry.name, 'guard.json')
      return { name: entry.name, templatePath }
    })
    .filter((entry) => fs.existsSync(entry.templatePath))
    .sort((left, right) => left.name.localeCompare(right.name))
    .map(({ name, templatePath }) => {
      const cfg = JSON.parse(fs.readFileSync(templatePath, 'utf8'))
      return {
        name,
        path: templatePath,
        source: 'template',
        description: cfg.metadata?.description || '',
        risk: cfg.metadata?.risk || 'unknown',
        status: cfg.metadata?.status || 'template',
        imports: Array.isArray(cfg.imports) ? cfg.imports : [],
      }
    })
}

const expandPath = (value, replacements, realHome) => {
  if (typeof value !== 'string') return value
  let expanded = value
  for (const [needle, replacement] of Object.entries(replacements)) {
    expanded = expanded.split(needle).join(replacement)
  }
  if (expanded === '~') return realHome
  if (expanded.startsWith('~/')) return `${realHome}${expanded.slice(1)}`
  return expanded
}

const expandConfig = (cfg, replacements, realHome) => {
  const expanded = structuredClone(cfg)

  if (expanded.filesystem && typeof expanded.filesystem === 'object') {
    for (const key of ['denyRead', 'allowRead', 'allowWrite', 'denyWrite']) {
      if (Array.isArray(expanded.filesystem[key])) {
        expanded.filesystem[key] = expanded.filesystem[key].map((value) =>
          expandPath(value, replacements, realHome),
        )
      }
    }
  } else {
    expanded.filesystem = {}
  }

  if (expanded.filesystem.denyRead === undefined) {
    expanded.filesystem.denyRead = [
      '/Users',
      '/Volumes',
      '/Applications',
      '/cores',
      '/home',
    ]
  }

  if (expanded.filesystem.allowRead === undefined) {
    expanded.filesystem.allowRead = [
      replacements['${GUARD_PROJECT_DIR}'],
      replacements['${GUARD_RUN_DIR}'],
    ].filter(
      (value, index, values) =>
        typeof value === 'string' &&
        value.length > 0 &&
        values.indexOf(value) === index,
    )
  }

  if (expanded.network && typeof expanded.network === 'object') {
    for (const key of ['allowUnixSockets']) {
      if (Array.isArray(expanded.network[key])) {
        expanded.network[key] = expanded.network[key].map((value) =>
          expandPath(value, replacements, realHome),
        )
      }
    }
    expanded.network = applyDeniedDomainPresets(expanded.network)
  }

  if (
    expanded.networkUnrestricted === true &&
    expanded.network &&
    typeof expanded.network === 'object'
  ) {
    delete expanded.network.allowedDomains
    delete expanded.network.deniedDomains
  }

  if (typeof expanded.workingDirectory === 'string') {
    expanded.workingDirectory = expandPath(
      expanded.workingDirectory,
      replacements,
      realHome,
    )
  }

  if (Array.isArray(expanded.homeLinks)) {
    expanded.homeLinks = expanded.homeLinks.map((entry) => ({
      source: expandPath(entry?.source, replacements, realHome),
      target: expandPath(entry?.target, replacements, realHome),
    }))
  }

  return expanded
}

const displayPath = (value, replacements, realHome, cwd) => {
  if (typeof value !== 'string') return String(value)
  const resolved = expandPath(value, replacements, realHome)
  if (realHome && resolved.startsWith(realHome)) {
    return `~${resolved.slice(realHome.length)}`
  }
  if (resolved.startsWith(cwd)) {
    return `.${resolved.slice(cwd.length)}`
  }
  return resolved
}

const getPolicyStatus = (cfg) => {
  const fsCfg = cfg.filesystem || {}
  const netCfg = cfg.network || {}
  const askNetwork = netCfg.ask === true
  const allowedDomains = Array.isArray(netCfg.allowedDomains)
    ? netCfg.allowedDomains
    : []
  const allowedRawTcp = Array.isArray(netCfg.allowedRawTcp)
    ? netCfg.allowedRawTcp
    : []
  const denyWrite = Array.isArray(fsCfg.denyWrite) ? fsCfg.denyWrite : []
  const secretsProtected = denyWrite.some((value) =>
    /(^|\/)(\.env|secrets\/|\*\.key|\*\.pem)/.test(String(value)),
  )
  const riskyDefaults = cfg.networkUnrestricted === true || !secretsProtected
  return {
    askNetwork,
    riskyDefaults,
    status: riskyDefaults ? 'review' : 'ok',
    riskText: riskyDefaults
      ? 'risky defaults need review'
      : 'no dangerous defaults detected',
    networkText: cfg.networkUnrestricted
      ? 'net unrestricted'
      : askNetwork
        ? 'net ask active'
        : allowedDomains.length > 0 || allowedRawTcp.length > 0
          ? 'net allowlist active'
          : 'net none',
    secretsText: secretsProtected ? 'secrets protected' : 'secrets not denied',
  }
}

const getBannerMode = () => {
  if (process.env.GUARD_QUIET === '1') return 'off'
  const mode = process.env.GUARD_BANNER || 'full'
  return ['compact', 'full', 'off'].includes(mode) ? mode : 'full'
}

const formatPolicyBanner = ({
  profile,
  cfg,
  guardRunDir,
  replacements,
  realHome,
  cwd,
  colorMode,
  tty,
}) => {
  const useColor =
    colorMode === 'always' || (colorMode !== 'never' && tty === true)
  const terminalWidth =
    Number.isInteger(process.stderr.columns) && process.stderr.columns > 0
      ? process.stderr.columns
      : 96
  const innerWidth = Math.max(76, Math.min(96, terminalWidth - 4))
  const labelWidth = 12
  const columnGap = 3
  const leftWidth = Math.floor((innerWidth - columnGap) / 2)
  const rightWidth = innerWidth - columnGap - leftWidth
  const c = {
    reset: useColor ? '\x1b[0m' : '',
    dim: useColor ? '\x1b[2m' : '',
    bold: useColor ? '\x1b[1m' : '',
    cyan: useColor ? '\x1b[36m' : '',
    green: useColor ? '\x1b[32m' : '',
    red: useColor ? '\x1b[31m' : '',
    yellow: useColor ? '\x1b[33m' : '',
  }
  const colorize = (value, color) =>
    color ? `${color}${value}${c.reset}` : value
  const stripAnsi = (value) => String(value).replace(/\x1b\[[0-9;]*m/g, '')
  const padVisible = (value, width) =>
    `${value}${' '.repeat(Math.max(0, width - stripAnsi(value).length))}`
  const compactPath = (value) => {
    const shown = displayPath(value, replacements, realHome, cwd)
    if (shown === guardRunDir) return '<run>'
    if (shown.startsWith(`${guardRunDir}/`)) {
      return `<run>${shown.slice(guardRunDir.length)}`
    }
    return shown
  }
  const list = (values, empty = '-') =>
    Array.isArray(values) && values.length > 0
      ? values
          .map((value) => compactPath(value))
          .join(' ')
      : empty
  const loopback = () => {
    if (netCfg.allowLoopbackConnections) return 'all'
    const values = []
    if (netCfg.allowLoopbackHighPorts) values.push('high')
    if (isLoopbackListeningHighPortsEnabled(netCfg.allowLoopbackListeningHighPorts)) {
      values.push('listening-high')
    }
    if (Array.isArray(netCfg.allowLoopbackPorts)) {
      values.push(...netCfg.allowLoopbackPorts)
    }
    return list(values, 'no')
  }
  const border = (fill = '-') =>
    `${c.dim}+${fill.repeat(innerWidth + 2)}+${c.reset}`
  const splitBorder = () =>
    `${c.dim}+${'-'.repeat(leftWidth + 2)}+${'-'.repeat(rightWidth + 2)}+${c.reset}`
  const title = profile === 'guard' ? 'guard' : `guard:${profile}`
  const titledBorder = (name) => {
    const shown = colorize(name, `${c.bold}${c.cyan}`)
    const label = ` ${shown} `
    const remaining = Math.max(0, innerWidth + 2 - stripAnsi(label).length)
    return `${c.dim}+${label}${'-'.repeat(remaining)}+${c.reset}`
  }
  const wrapValue = (value, width) => {
    if (!value) return ['-']
    if (value.length <= width) return [value]

    const words = value.split(' ')
    const lines = []
    const pushLongWord = (word) => {
      let remaining = word
      while (remaining.length > width) {
        lines.push(remaining.slice(0, width))
        remaining = remaining.slice(width)
      }
      return remaining
    }
    let current = ''
    for (const word of words) {
      if (word.length > width) {
        if (current) {
          lines.push(current)
          current = ''
        }
        current = pushLongWord(word)
        continue
      }
      if (!current) {
        current = word
        continue
      }
      if ((current + ' ' + word).length <= width) {
        current += ' ' + word
      } else {
        lines.push(current)
        current = word
      }
    }
    if (current) lines.push(current)
    return lines
  }
  const frameLine = (value) => `| ${padVisible(value, innerWidth)} |`
  const twoColumnLine = (left, right) =>
    `| ${padVisible(left, leftWidth)} | ${padVisible(right, rightWidth)} |`
  const renderPolicyCells = (key, values, color, width) => {
    const valueWidth = Math.max(8, width - labelWidth - 1)
    const wrapped = wrapValue(list(values), valueWidth)
    return wrapped.map((chunk, index) => {
      const plainKey =
        index === 0 ? key.padEnd(labelWidth, ' ') : ''.padEnd(labelWidth, ' ')
      const shownKey = index === 0 ? colorize(plainKey, color) : plainKey
      return `${shownKey} ${chunk}`
    })
  }
  const renderRuntimeRows = (key, value, color = '') => {
    const valueWidth = Math.max(8, innerWidth - labelWidth - 1)
    const wrapped = wrapValue(value, valueWidth)
    return wrapped.map((chunk, index) => {
      const plainKey =
        index === 0 ? key.padEnd(labelWidth, ' ') : ''.padEnd(labelWidth, ' ')
      const shownKey = index === 0 ? colorize(plainKey, color) : plainKey
      return frameLine(`${shownKey} ${chunk}`)
    })
  }

  const fsCfg = cfg.filesystem || {}
  const netCfg = cfg.network || {}
  const policyStatus = getPolicyStatus(cfg)
  const rawTcpSummary = Array.isArray(netCfg.allowedRawTcp) && netCfg.allowedRawTcp.length > 0
    ? `raw=${netCfg.allowedRawTcp.map((rule) => `${rule.host || rule.ip || '?'}:${rule.port || '?'}`).join(' ')}`
    : null
  const netSummary = cfg.networkUnrestricted
    ? 'unrestricted'
    : policyStatus.askNetwork
      ? [list(netCfg.allowedDomains, 'none'), rawTcpSummary, '+ ask']
          .filter((value) => value)
          .join(' ')
      : [
          list(netCfg.allowedDomains, 'none'),
          rawTcpSummary,
        ]
          .filter((value) => value)
          .join(' ')
  const statusColor = policyStatus.riskyDefaults ? c.yellow : c.green
  const status = `${colorize(
    policyStatus.status.padEnd(labelWidth, ' '),
    statusColor,
  )} ${[
    policyStatus.riskText,
    policyStatus.networkText,
    policyStatus.secretsText,
  ].join('  ')}`
  const allowCells = [
    ...renderPolicyCells('✓ read', fsCfg.allowRead, c.green, leftWidth),
    ...renderPolicyCells('✓ write', fsCfg.allowWrite, c.green, leftWidth),
  ]
  const denyCells = [
    ...renderPolicyCells('× read', fsCfg.denyRead, c.red, rightWidth),
    ...renderPolicyCells('× write', fsCfg.denyWrite, c.red, rightWidth),
  ]
  const policyRows = []
  for (let index = 0; index < Math.max(allowCells.length, denyCells.length); index += 1) {
    policyRows.push(twoColumnLine(allowCells[index] || '', denyCells[index] || ''))
  }
  const lines = [
    frameLine(status),
    frameLine(`${colorize('run'.padEnd(labelWidth, ' '), c.dim)} ${guardRunDir}`),
    ...(cfg.workingDirectory
      ? [
          frameLine(
            `${colorize('cwd'.padEnd(labelWidth, ' '), c.dim)} ${displayPath(
              cfg.workingDirectory,
              replacements,
              realHome,
              cwd,
            )}`,
          ),
        ]
      : []),
    splitBorder(),
    ...policyRows,
    titledBorder('runtime'),
    ...renderRuntimeRows(
      'network',
      netSummary,
      cfg.networkUnrestricted ? c.yellow : c.green,
    ),
    ...renderRuntimeRows(
      'local',
      `bind=${netCfg.allowLocalBinding ? 'yes' : 'no'} loopback=${loopback()} pty=${cfg.allowPty ? 'yes' : 'no'} unix=${list(
        netCfg.allowUnixSockets,
        'none',
      )}`,
      netCfg.allowLocalBinding ||
      netCfg.allowLoopbackConnections ||
      netCfg.allowLoopbackHighPorts ||
      isLoopbackListeningHighPortsEnabled(netCfg.allowLoopbackListeningHighPorts) ||
      (Array.isArray(netCfg.allowLoopbackPorts) &&
        netCfg.allowLoopbackPorts.length > 0) ||
      cfg.allowPty
        ? c.green
        : c.yellow,
    ),
  ]

  return `${[
    titledBorder(`${title} policy`),
    ...lines,
    border(),
  ].join('\n')}\n`
}

const formatCompactPolicyBanner = ({ profile, cfg, guardRunDir, colorMode, tty }) => {
  const useColor =
    colorMode === 'always' || (colorMode !== 'never' && tty === true)
  const c = {
    reset: useColor ? '\x1b[0m' : '',
    cyan: useColor ? '\x1b[36m' : '',
    green: useColor ? '\x1b[32m' : '',
    yellow: useColor ? '\x1b[33m' : '',
  }
  const colorize = (value, color) =>
    color ? `${color}${value}${c.reset}` : value
  const title = profile === 'guard' ? 'guard' : `guard:${profile}`
  const policyStatus = getPolicyStatus(cfg)
  const statusColor = policyStatus.riskyDefaults ? c.yellow : c.green
  const line = [
    `${colorize(title, c.cyan)} ${colorize(policyStatus.status, statusColor)}`,
    policyStatus.networkText,
    policyStatus.secretsText,
    `run=${guardRunDir}`,
  ].join('  ')
  return `${line}\n`
}

const getShimDirs = ({ invokedPath, realHome }) => {
  const dirs = new Set()
  const addDir = (candidate) => {
    if (!candidate) return
    dirs.add(safeRealpath(candidate))
  }

  addDir(process.env.GUARD_SHIM_DIR)
  for (const candidate of (process.env.GUARD_SHIM_DIRS || '')
    .split(':')
    .filter(Boolean)) {
    addDir(candidate)
  }
  if (realHome) {
    addDir(path.join(realHome, '.local', 'bin'))
  }
  if (invokedPath) {
    addDir(path.dirname(invokedPath))
  }
  return [...dirs]
}

const sanitizePath = (pathValue, shimDirs) => {
  const blocked = new Set(shimDirs.map((dir) => safeRealpath(dir)))
  const seen = new Set()
  const parts = []
  for (const segment of (pathValue || '').split(':')) {
    if (!segment || /\s/.test(segment)) continue
    const normalized = safeRealpath(segment)
    if (blocked.has(normalized)) continue
    if (seen.has(normalized)) continue
    seen.add(normalized)
    parts.push(segment)
  }
  return parts.join(':')
}

const parseFlagValue = (args, index) => {
  if (!args[index + 1]) {
    throw new Error(`missing value for ${args[index]}`)
  }
  return args[index + 1]
}

const APP_COMMANDS = new Set(['webex', 'teams', 'zoom'])

const ensureParentDir = (target) => {
  fs.mkdirSync(path.dirname(target), { recursive: true })
}

const expandHome = (value) => {
  if (typeof value !== 'string') return value
  if (value === '~') return process.env.HOME || value
  if (value.startsWith('~/')) {
    return process.env.HOME ? path.join(process.env.HOME, value.slice(2)) : value
  }
  return value
}

const resolveGuardConfigDir = () => {
  if (process.env.GUARD_CONFIG_DIR) {
    return path.resolve(expandHome(process.env.GUARD_CONFIG_DIR))
  }
  if (process.env.XDG_CONFIG_HOME) {
    return path.join(path.resolve(expandHome(process.env.XDG_CONFIG_HOME)), 'guard')
  }
  if (process.env.HOME) {
    return path.join(process.env.HOME, '.config', 'guard')
  }
  return null
}

const resolveGuardConfigPath = () => {
  const configDir = resolveGuardConfigDir()
  return configDir ? path.join(configDir, 'config.json') : null
}

const resolveGuardStateDir = () => {
  if (process.env.GUARD_STATE_DIR) {
    return path.resolve(expandHome(process.env.GUARD_STATE_DIR))
  }
  if (process.env.HOME) {
    return path.join(process.env.HOME, 'Library', 'Application Support', 'guard')
  }
  return path.resolve('/tmp/guard-state')
}

const resolveGuardEventLogPath = () => {
  if (process.env.GUARD_EVENT_LOG) {
    return path.resolve(expandHome(process.env.GUARD_EVENT_LOG))
  }
  return path.join(resolveGuardStateDir(), 'events.jsonl')
}

const readGuardUserConfig = () => {
  const configPath = resolveGuardConfigPath()
  if (!configPath || !fs.existsSync(configPath)) return {}
  try {
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'))
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  } catch {
    return {}
  }
}

const collectManagedRootInfo = () => {
  const configPath = resolveGuardConfigPath()
  if (process.env.GUARD_CODE_ROOT) {
    return {
      root: path.resolve(expandHome(process.env.GUARD_CODE_ROOT)),
      source: 'GUARD_CODE_ROOT',
      configPath,
    }
  }
  const userConfig = readGuardUserConfig()
  if (typeof userConfig.codeRoot === 'string' && userConfig.codeRoot.trim()) {
    return {
      root: path.resolve(expandHome(userConfig.codeRoot)),
      source: configPath || 'user config',
      configPath,
    }
  }
  if (process.env.HOME) {
    return {
      root: path.join(process.env.HOME, 'code'),
      source: 'default',
      configPath,
    }
  }
  return {
    root: process.cwd(),
    source: 'cwd fallback',
    configPath,
  }
}

const resolveManagedRoot = () => collectManagedRootInfo().root

const writeGuardUserConfig = ({ codeRoot, installBinDir = null, includeShims = null }) => {
  const configPath = resolveGuardConfigPath()
  if (!configPath) {
    throw new Error('HOME or GUARD_CONFIG_DIR is required to write guard config')
  }
  const existing = readGuardUserConfig()
  const next = {
    ...existing,
    codeRoot: path.resolve(expandHome(codeRoot)),
  }
  if (installBinDir !== null) {
    next.installBinDir = path.resolve(expandHome(installBinDir))
  }
  if (includeShims !== null) {
    next.includeShims = includeShims === true
  }
  ensureParentDir(configPath)
  fs.writeFileSync(configPath, `${JSON.stringify(next, null, 2)}\n`)
  return { configPath, config: next }
}

const resolveInstallBinDir = () => {
  if (process.env.GUARD_INSTALL_BIN_DIR) {
    return path.resolve(process.env.GUARD_INSTALL_BIN_DIR)
  }
  const userConfig = readGuardUserConfig()
  if (typeof userConfig.installBinDir === 'string' && userConfig.installBinDir.trim()) {
    return path.resolve(expandHome(userConfig.installBinDir))
  }
  const realHome = process.env.HOME || ''
  if (!realHome) {
    throw new Error('HOME is required to resolve the default install directory')
  }
  return path.join(realHome, '.local', 'bin')
}

const linkTarget = (target, source, { force = false } = {}) => {
  ensureParentDir(target)
  let existing = null
  try {
    existing = fs.lstatSync(target)
  } catch {}
  if (existing) {
    if (existing.isSymbolicLink()) {
      const current = fs.readlinkSync(target)
      if (current === source) {
        return 'unchanged'
      }
    }
    if (!force) {
      throw new Error(`refusing to replace existing path without --force: ${target}`)
    }
    fs.rmSync(target, { force: true, recursive: true })
  }
  fs.symlinkSync(source, target)
  return 'linked'
}

const createProjectFromTemplate = ({
  repoRoot,
  cwd,
  template = 'node-app',
  force = false,
}) => {
  const templatePath = path.resolve(repoRoot, 'templates', template, 'guard.json')
  if (!fs.existsSync(templatePath)) {
    throw new Error(`unknown template: ${template}`)
  }

  const guardDir = path.join(cwd, '.guard')
  const targetPath = path.join(guardDir, 'guard.json')
  fs.mkdirSync(guardDir, { recursive: true })

  if (fs.existsSync(targetPath) && !force) {
    throw new Error(`refusing to overwrite existing config without --force: ${targetPath}`)
  }

  fs.copyFileSync(templatePath, targetPath)
  return { templatePath, targetPath }
}

const findExecutableInPath = (name, pathValue) => {
  for (const segment of (pathValue || '').split(':')) {
    if (!segment) continue
    const candidate = path.join(segment, name)
    try {
      fs.accessSync(candidate, fs.constants.X_OK)
      return safeRealpath(candidate)
    } catch {}
  }
  return null
}

const resolveToolCommand = (tool, sanitizedPath) => {
  const spec = TOOL_SPECS[tool]
  if (!spec) {
    return {
      status: 'unsupported',
      tool,
      reason: `unsupported tool: ${tool}`,
    }
  }

  const override = process.env[spec.overrideEnv]
  if (override) {
    ensureExecutable(override, `guard: ${tool}`)
    return {
      status: 'resolved',
      tool,
      source: 'override',
      command: [safeRealpath(override)],
      path: safeRealpath(override),
      sanitizedPath,
    }
  }

  for (const lookupName of spec.lookup) {
    const found = findExecutableInPath(lookupName, sanitizedPath)
    if (found) {
      return {
        status: 'resolved',
        tool,
        source: 'path',
        lookupName,
        command: [found],
        path: found,
        sanitizedPath,
      }
    }
  }

  for (const fallback of spec.fallbacks || []) {
    try {
      ensureExecutable(fallback, `guard: ${tool}`)
      return {
        status: 'resolved',
        tool,
        source: 'fallback',
        path: fallback,
        command: [fallback],
        sanitizedPath,
      }
    } catch {}
  }

  return {
    status: 'missing',
    tool,
    reason: `could not resolve real ${tool} from sanitized PATH`,
    sanitizedPath,
  }
}

const collectDoctorInfo = ({
  repoRoot,
  invokedPath,
  cwd,
  profile = 'guard',
  targetTool = null,
}) => {
  const realHome = process.env.HOME || ''
  const managedRoot = collectManagedRootInfo()
  const codeRoot = managedRoot.root
  const shimDirs = getShimDirs({ invokedPath, realHome })
  const sanitizedPath = sanitizePath(process.env.PATH || '', shimDirs)
  const projectProfile = findNearestProfile(cwd, profile)
  const builtInProfile = findBuiltInProfile(repoRoot, profile, cwd)
  const effectiveProfile = projectProfile || builtInProfile
  const resolvedNode = resolveToolCommand('node', sanitizedPath)
  const tools =
    targetTool !== null
      ? { [targetTool]: resolveToolCommand(targetTool, sanitizedPath) }
      : Object.fromEntries(
          RESOLVABLE_SHIM_TOOLS.map((tool) => [
            tool,
            resolveToolCommand(tool, sanitizedPath),
          ]),
        )

  return {
    cwd,
    codeRoot,
    codeRootSource: managedRoot.source,
    guardConfigPath: managedRoot.configPath,
    insideManagedRoot: isInsideRoot(cwd, codeRoot),
    repoRoot,
    invokedPath,
    shimDirs,
    sanitizedPath,
    profile,
    projectProfile: projectProfile?.config || null,
    builtInProfile: builtInProfile?.config || null,
    effectiveProfile: effectiveProfile?.config || null,
    effectiveProfileSource: effectiveProfile?.source || null,
    runtimeNode: resolvedNode,
    tools,
    disabledTools: [...DISABLED_TOOLS],
  }
}

const formatDoctorText = (info) => {
  const lines = [
    'Guard Doctor',
    `cwd: ${info.cwd}`,
    `managed root: ${info.codeRoot}`,
    `managed root source: ${info.codeRootSource}`,
    `user config: ${info.guardConfigPath || '-'}`,
    `inside managed root: ${info.insideManagedRoot ? 'yes' : 'no'}`,
    `profile: ${info.profile}`,
    `project profile: ${info.projectProfile || '-'}`,
    `built-in profile: ${info.builtInProfile || '-'}`,
    `effective profile: ${info.effectiveProfile || '-'}`,
    `effective profile source: ${info.effectiveProfileSource || '-'}`,
    `shim dirs: ${info.shimDirs.length > 0 ? info.shimDirs.join(' ') : '-'}`,
    `sanitized PATH: ${info.sanitizedPath || '-'}`,
    `runtime node: ${info.runtimeNode.status === 'resolved' ? `${info.runtimeNode.path} (${info.runtimeNode.source})` : info.runtimeNode.reason}`,
    'resolved tools:',
  ]
  for (const [tool, resolution] of Object.entries(info.tools)) {
    if (resolution.status === 'resolved') {
      lines.push(`  ${tool}: ${resolution.path} (${resolution.source})`)
    } else {
      lines.push(`  ${tool}: ${resolution.reason}`)
    }
  }
  lines.push(`disabled tools: ${info.disabledTools.join(' ')}`)
  return `${lines.join('\n')}\n`
}

const resolveProfileConfig = ({ repoRoot, cwd, profile }) => {
  const resolved =
    findNearestProfile(cwd, profile) || findBuiltInProfile(repoRoot, profile, cwd)
  if (!resolved) {
    throw new Error(
      `guard: no .guard/${profile}.json found above ${cwd} and no built-in profiles/${profile}.json`,
    )
  }
  return resolved
}

const createRuntimeContext = ({ resolved, cwd }) => {
  const realHome = process.env.HOME || ''
  const hash = crypto
    .createHash('sha256')
    .update(`${resolved.config}:${cwd}`)
    .digest('hex')
    .slice(0, 16)

  const guardHomeBase = process.env.GUARD_HOME_BASE || '/private/tmp/guard'
  const guardRun = path.join(guardHomeBase, `run-${hash}`)
  const guardHome = path.join(guardRun, 'home')
  const guardTmp = path.join(guardRun, 'tmp')
  const guardDockerConfig = path.join(guardRun, 'docker-config')
  const realTmpdir = (process.env.TMPDIR || '/tmp').replace(/\/+$/, '') || '/tmp'
  const replacements = {
    '${GUARD_RUN_DIR}': guardRun,
    '${GUARD_HOME_DIR}': guardHome,
    '${GUARD_TMP_DIR}': guardTmp,
    '${GUARD_PROJECT_DIR}': resolved.projectDir,
    '${GUARD_CWD}': cwd,
    '${GUARD_REAL_HOME}': realHome,
    '${GUARD_REAL_TMPDIR}': realTmpdir,
  }
  return {
    realHome,
    guardRun,
    guardHome,
    guardTmp,
    guardDockerConfig,
    realTmpdir,
    replacements,
    runtimeConfigPath: path.join(guardTmp, 'config.json'),
    profilePath: path.join(guardTmp, 'profile.sb'),
  }
}

const loadExpandedProfile = ({ repoRoot, cwd, profile }) => {
  const resolved = resolveProfileConfig({ repoRoot, cwd, profile })
  const runtime = createRuntimeContext({ resolved, cwd })
  const raw = loadProfileConfig({ repoRoot, configPath: resolved.config })
  const cfg = expandConfig(raw, runtime.replacements, runtime.realHome)
  return { resolved, runtime, raw, cfg }
}

const isPathAtOrInside = (value, root) => {
  if (typeof value !== 'string' || !value) return false
  const normalized = path.resolve(value)
  const normalizedRoot = path.resolve(root)
  return (
    normalized === normalizedRoot ||
    normalized.startsWith(`${normalizedRoot}${path.sep}`)
  )
}

const hasGlob = (value) => typeof value === 'string' && /[*?[\]{}]/.test(value)

const isBroadUsersAccess = (value) => {
  if (typeof value !== 'string') return false
  const normalized = value.replace(/\/+$/, '')
  if (normalized === '/Users') return true
  const parts = normalized.split('/').filter(Boolean)
  if (parts[0] !== 'Users') return false
  if (parts.length === 2) return true
  return parts.length === 3 && (parts[2] === '*' || parts[2] === '**')
}

const isBroadVolumesAccess = (value) => {
  if (typeof value !== 'string') return false
  const normalized = value.replace(/\/+$/, '')
  if (normalized === '/Volumes') return true
  const parts = normalized.split('/').filter(Boolean)
  return (
    parts[0] === 'Volumes' &&
    parts.length === 2 &&
    (parts[1] === '*' || parts[1] === '**')
  )
}

const addFinding = (findings, severity, id, message, values = []) => {
  findings.push({ severity, id, message, values })
}

const auditExpandedPolicy = ({ cfg, configPath, profile, source, cwd }) => {
  const findings = []
  const fsCfg = cfg.filesystem || {}
  const netCfg = cfg.network || {}
  const allowRead = Array.isArray(fsCfg.allowRead) ? fsCfg.allowRead : []
  const allowWrite = Array.isArray(fsCfg.allowWrite) ? fsCfg.allowWrite : []
  const unixSockets = Array.isArray(netCfg.allowUnixSockets)
    ? netCfg.allowUnixSockets
    : []
  const machLookups = Array.isArray(netCfg.allowMachLookup)
    ? netCfg.allowMachLookup
    : []
  const allowedPaths = [...allowRead, ...allowWrite]

  const broadUsers = allowedPaths.filter(isBroadUsersAccess)
  if (broadUsers.length > 0) {
    addFinding(
      findings,
      'high',
      'broad-users-access',
      'Policy broadly allows access under /Users; prefer explicit project or app data carve-outs.',
      broadUsers,
    )
  }

  const broadVolumes = allowedPaths.filter(isBroadVolumesAccess)
  if (broadVolumes.length > 0) {
    addFinding(
      findings,
      'high',
      'volumes-access',
      'Policy allows mounted volume access; removable/network volumes often contain unrelated sensitive data.',
      broadVolumes,
    )
  }

  const homeDockerSocket = process.env.HOME
    ? path.join(process.env.HOME, '.docker/run/docker.sock')
    : ''
  const dockerSockets = unixSockets.filter((value) =>
    [
      '/var/run/docker.sock',
      '/private/var/run/docker.sock',
      homeDockerSocket,
    ].some((socketPath) => socketPath && isPathAtOrInside(value, socketPath)),
  )
  if (dockerSockets.length > 0) {
    addFinding(
      findings,
      'critical',
      'docker-socket-access',
      'Policy allows Docker socket access, which is effectively host-level code execution.',
      dockerSockets,
    )
  }

  if (cfg.networkUnrestricted === true) {
    addFinding(
      findings,
      'critical',
      'network-unrestricted',
      'networkUnrestricted disables domain filtering and allows direct network egress.',
    )
  }
  if (netCfg.allowLoopbackHighPorts === true) {
    addFinding(
      findings,
      'medium',
      'loopback-high-ports-expansion',
      'allowLoopbackHighPorts emits one sandbox rule per ephemeral port, can slow startup, and allows unrelated high-port loopback services; prefer exact allowLoopbackPorts or allowLoopbackListeningHighPorts when possible.',
    )
  }

  const broadSockets = unixSockets.filter((value) =>
    value === '/' ||
    value === '/tmp' ||
    value === '/private/tmp' ||
    value === '/var' ||
    value === '/private/var' ||
    value === '/Users' ||
    value === '/Volumes' ||
    hasGlob(value),
  )
  if (broadSockets.length > 0) {
    addFinding(
      findings,
      'high',
      'broad-unix-socket-access',
      'Policy allows broad Unix socket paths; prefer a single socket file or guard run directory.',
      broadSockets,
    )
  }

  const broadMach = machLookups.filter((value) =>
    typeof value === 'string' &&
    (value === '*' ||
      value === 'com.apple.*' ||
      value.endsWith('.*') ||
      value.endsWith('*')),
  )
  if (broadMach.length > 0) {
    addFinding(
      findings,
      'medium',
      'broad-mach-lookup',
      'Policy allows broad Mach lookup patterns; prefer exact service names or tight prefixes.',
      broadMach,
    )
  }

  return {
    profile,
    source,
    configPath,
    cwd,
    findingCount: findings.length,
    findings,
  }
}

const REQUIRED_DENY_READ_ROOTS = ['/Users', '/Volumes', '/Applications', '/cores', '/home']
const REQUIRED_SECRET_DENY_WRITES = ['.env', '.env.*', 'secrets/', '*.key', '*.pem']

const collectProfileDoctor = ({ raw, cfg, audit, configPath, profile, source }) => {
  const findings = [...audit.findings]
  const fsCfg = cfg.filesystem || {}
  const netCfg = cfg.network || {}
  const metadata = raw.metadata || {}
  const denyRead = Array.isArray(fsCfg.denyRead) ? fsCfg.denyRead : []
  const denyWrite = Array.isArray(fsCfg.denyWrite) ? fsCfg.denyWrite : []
  const allowRead = Array.isArray(fsCfg.allowRead) ? fsCfg.allowRead : []
  const allowedDomains = Array.isArray(netCfg.allowedDomains)
    ? netCfg.allowedDomains
    : []

  for (const root of REQUIRED_DENY_READ_ROOTS) {
    if (!denyRead.includes(root)) {
      addFinding(
        findings,
        'high',
        'missing-critical-deny-read',
        `Profile should deny reads from ${root}.`,
        [root],
      )
    }
  }

  const missingSecrets = REQUIRED_SECRET_DENY_WRITES.filter(
    (entry) => !denyWrite.includes(entry),
  )
  if (missingSecrets.length > 0) {
    addFinding(
      findings,
      'medium',
      'missing-secret-write-denies',
      'Profile should deny common secret-file writes even inside writable areas.',
      missingSecrets,
    )
  }

  const httpRules = Array.isArray(netCfg.httpRules) ? netCfg.httpRules : []
  if (
    !cfg.networkUnrestricted &&
    netCfg.ask !== true &&
    allowedDomains.length === 0 &&
    httpRules.length === 0 &&
    allowedRawTcp.length === 0
  ) {
    addFinding(
      findings,
      'medium',
      'no-network-policy',
      'Profile has neither networkUnrestricted, allowedDomains, allowedRawTcp, httpRules, nor network.ask enabled.',
    )
  }

  if (source === 'builtin') {
    for (const key of ['description', 'risk', 'status']) {
      if (!metadata[key]) {
        addFinding(
          findings,
          'low',
          'missing-profile-metadata',
          `Built-in profile is missing metadata.${key}.`,
          [key],
        )
      }
    }
  }

  if (metadata.appBundle && !allowRead.includes(metadata.appBundle)) {
    addFinding(
      findings,
      'high',
      'app-bundle-not-reopened',
      'metadata.appBundle is not present in filesystem.allowRead.',
      [metadata.appBundle],
    )
  }

  const unknownPresets = (Array.isArray(raw.network?.deniedDomainPresets)
    ? raw.network.deniedDomainPresets
    : []
  ).filter((preset) => !DENIED_DOMAIN_PRESETS[preset])
  if (unknownPresets.length > 0) {
    addFinding(
      findings,
      'medium',
      'unknown-denied-domain-preset',
      'Profile references unknown deniedDomainPresets entries.',
      unknownPresets,
    )
  }

  return {
    profile,
    source,
    configPath,
    status: findings.some((finding) => ['critical', 'high'].includes(finding.severity))
      ? 'review'
      : findings.length > 0
        ? 'warn'
        : 'ok',
    findingCount: findings.length,
    findings,
  }
}

const formatAuditText = (audit) => {
  const lines = [
    'Guard Audit',
    `cwd: ${audit.cwd}`,
    `profile: ${audit.profile}`,
    `effective profile: ${audit.configPath || '-'}`,
    `effective profile source: ${audit.source || '-'}`,
  ]

  if (audit.findings.length === 0) {
    lines.push('findings: none')
    return `${lines.join('\n')}\n`
  }

  lines.push(`findings: ${audit.findings.length}`)
  for (const finding of audit.findings) {
    lines.push(`- [${finding.severity}] ${finding.id}: ${finding.message}`)
    if (finding.values?.length > 0) {
      lines.push(`  values: ${finding.values.join(' ')}`)
    }
  }
  return `${lines.join('\n')}\n`
}

const formatProfileDoctorText = (doctor) => {
  const lines = [
    'Guard Profile Doctor',
    `profile: ${doctor.profile}`,
    `status: ${doctor.status}`,
    `source: ${doctor.source || '-'}`,
    `config: ${doctor.configPath || '-'}`,
  ]
  if (doctor.findings.length === 0) {
    lines.push('findings: none')
    return `${lines.join('\n')}\n`
  }
  lines.push(`findings: ${doctor.findings.length}`)
  for (const finding of doctor.findings) {
    lines.push(`- [${finding.severity}] ${finding.id}: ${finding.message}`)
    if (finding.values?.length > 0) {
      lines.push(`  values: ${finding.values.join(' ')}`)
    }
  }
  return `${lines.join('\n')}\n`
}

const normalizeTlsInspection = (network = {}) => {
  const raw = network.tlsInspection && typeof network.tlsInspection === 'object'
    ? network.tlsInspection
    : {}
  const explicit = Object.prototype.hasOwnProperty.call(network, 'tlsInspection')
  const enabled = typeof raw.enabled === 'boolean'
    ? raw.enabled
    : network.backend === 'iron-proxy'
  return {
    enabled,
    explicit,
    mode: raw.mode || (enabled ? 'ephemeral-run-ca' : 'off'),
    caScope: raw.caScope || (enabled ? 'guarded-process-env' : 'none'),
    trustedBy: Array.isArray(raw.trustedBy)
      ? raw.trustedBy
      : enabled
        ? ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'GIT_SSL_CAINFO']
        : [],
    userApprovalRequired: raw.userApprovalRequired !== false,
  }
}

const formatTlsInspectionText = (summary) => [
  'Guard TLS Inspection',
  `profile: ${summary.profile}`,
  `config: ${summary.configPath}`,
  `network backend: ${summary.networkBackend}`,
  `enabled: ${summary.tlsInspection.enabled ? 'yes' : 'no'}`,
  `explicit profile setting: ${summary.tlsInspection.explicit ? 'yes' : 'no'}`,
  `mode: ${summary.tlsInspection.mode}`,
  `CA scope: ${summary.tlsInspection.caScope}`,
  `trusted by: ${summary.tlsInspection.trustedBy.join(', ') || '-'}`,
  `approval required: ${summary.tlsInspection.userApprovalRequired ? 'yes' : 'no'}`,
].join('\n') + '\n'

const collectTlsInspectionStatus = ({ repoRoot, cwd, profile }) => {
  const { resolved, cfg } = loadExpandedProfile({ repoRoot, cwd, profile })
  const network = cfg.network || {}
  return {
    profile,
    source: resolved.source,
    configPath: resolved.config,
    networkBackend: network.backend || 'guard',
    deepHttpPolicy: Array.isArray(network.httpRules) && network.httpRules.length > 0,
    tlsInspection: normalizeTlsInspection(network),
  }
}

const runTlsStatus = ({ repoRoot, cwd, profile, json }) => {
  const status = collectTlsInspectionStatus({ repoRoot, cwd, profile })
  if (json) {
    emit(process.stdout, JSON.stringify(status, null, 2))
  } else {
    process.stdout.write(formatTlsInspectionText(status))
  }
  process.exit(0)
}

const collectSettings = ({ repoRoot, cwd, profile }) => {
  const monitorLog = resolveGuardEventLogPath()
  const stateDir = resolveGuardStateDir()
  const tls = collectTlsInspectionStatus({ repoRoot, cwd, profile })
  return {
    profile,
    cwd,
    stateDir,
    eventLogPath: monitorLog,
    askNetworkUi: process.env.GUARD_ASK_NETWORK_UI || 'auto',
    askNetworkHelper: process.env.GUARD_ASK_NETWORK_HELPER || null,
    daemon: {
      host: process.env.GUARDD_HOST || '127.0.0.1',
      port: Number(process.env.GUARDD_PORT || 8765),
      url: `http://${process.env.GUARDD_HOST || '127.0.0.1'}:${Number(process.env.GUARDD_PORT || 8765)}`,
    },
    tlsInspection: tls.tlsInspection,
  }
}

const formatSettingsText = (settings) => [
  'Guard Settings',
  `profile: ${settings.profile}`,
  `state dir: ${settings.stateDir}`,
  `event log: ${settings.eventLogPath}`,
  `ask UI: ${settings.askNetworkUi}`,
  `ask helper: ${settings.askNetworkHelper || '-'}`,
  `daemon: ${settings.daemon.url}`,
  `TLS inspection: ${settings.tlsInspection.enabled ? settings.tlsInspection.mode : 'off'}`,
].join('\n') + '\n'

const runSettings = ({ repoRoot, cwd, profile, json }) => {
  const settings = collectSettings({ repoRoot, cwd, profile })
  if (json) {
    emit(process.stdout, JSON.stringify(settings, null, 2))
  } else {
    process.stdout.write(formatSettingsText(settings))
  }
  process.exit(0)
}

const formatBuiltInProfilesText = (profiles) => {
  const lines = ['Built-in Guard Profiles']
  if (profiles.length === 0) {
    lines.push('  none')
    return `${lines.join('\n')}\n`
  }

  const nameWidth = Math.max(...profiles.map((profile) => profile.name.length), 4)
  for (const profile of profiles) {
    const app =
      profile.appBundle
        ? ` app=${profile.appBundle}`
        : ''
    const launcher = profile.launcher ? ` launcher=${profile.launcher}` : ''
    const description = profile.description ? ` ${profile.description}` : ''
    lines.push(
      `  ${profile.name.padEnd(nameWidth)}  status=${profile.status} risk=${profile.risk} network=${profile.network} domains=${profile.allowedDomainsCount}${launcher}${app}${description}`,
    )
  }
  return `${lines.join('\n')}\n`
}

const formatProjectTemplatesText = (templates) => {
  const lines = ['Guard Project Templates']
  if (templates.length === 0) {
    lines.push('  none')
    return `${lines.join('\n')}\n`
  }

  const nameWidth = Math.max(...templates.map((template) => template.name.length), 4)
  for (const template of templates) {
    const imports = template.imports.length > 0
      ? ` imports=${template.imports.join(',')}`
      : ''
    const description = template.description ? ` ${template.description}` : ''
    lines.push(
      `  ${template.name.padEnd(nameWidth)}  status=${template.status} risk=${template.risk}${imports}${description}`,
    )
  }
  return `${lines.join('\n')}\n`
}

const formatDomainPresetsText = () => {
  const names = Object.keys(DENIED_DOMAIN_PRESETS).sort()
  const lines = ['Denied Domain Presets']
  for (const name of names) {
    lines.push(`  ${name}: ${DENIED_DOMAIN_PRESETS[name].join(' ')}`)
  }
  return `${lines.join('\n')}\n`
}

const confirmUnsandboxed = async (tool, cwd) => {
  emit(process.stderr, `${tool} guard: no .guard/guard.json found above ${cwd}`)
  if (!(process.stdin.isTTY && process.stderr.isTTY)) {
    emit(
      process.stderr,
      `${tool} guard: refusing unsandboxed ${tool} in non-interactive shell`,
    )
    return false
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  })
  const reply = await rl.question(`Run ${tool} without sandbox? [y/N] `)
  rl.close()
  return /^(y|yes)$/i.test(reply.trim())
}

const parseGuardArgs = (argv) => {
  const args = [...argv]
  let profile = 'guard'
  let askNetwork = false
  let deepEgress = false

  if (args[0] === '-h' || args[0] === '--help' || args[0] === 'help') {
    return { mode: 'help' }
  }
  while (args.length > 0) {
    if (args[0] === '--profile') {
      if (!args[1]) return { mode: 'usage-error' }
      profile = args[1]
      args.splice(0, 2)
      continue
    }
    if (args[0] === '--ask-network') {
      askNetwork = true
      args.shift()
      continue
    }
    if (args[0] === '--deep-egress') {
      deepEgress = true
      args.shift()
      continue
    }
    break
  }
  if (args[0] === '-h' || args[0] === '--help' || args[0] === 'help') {
    return { mode: 'help' }
  }
  if (args[0] === '--') {
    args.shift()
  }

  if (
    (args[0] === 'run' && APP_COMMANDS.has(args[1])) ||
    APP_COMMANDS.has(args[0])
  ) {
    const appName = args[0] === 'run' ? args[1] : args[0]
    const appArgs = args[0] === 'run' ? args.slice(2) : args.slice(1)
    return {
      mode: 'app',
      appName,
      args: appArgs,
    }
  }

  if (args[0] === 'doctor') {
    args.shift()
    let json = false
    const filtered = []
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        filtered.push(arg)
      }
    }
    return {
      mode: 'doctor',
      profile,
      json,
      tool: filtered[0] || null,
    }
  }

  if (args[0] === 'audit') {
    args.shift()
    let json = false
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'audit',
      profile,
      json,
    }
  }

  if (args[0] === 'settings') {
    args.shift()
    let json = false
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'settings',
      profile,
      json,
    }
  }

  if (args[0] === 'tls' && args[1] === 'status') {
    args.splice(0, 2)
    let json = false
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'tls-status',
      profile,
      json,
    }
  }

  if (args[0] === 'app-summary') {
    args.shift()
    let json = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--json') {
        json = true
      } else if (arg === '--profile') {
        profile = parseFlagValue(args, index)
        index += 1
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'app-summary',
      profile,
      json,
    }
  }

  if (args[0] === 'daemon' || args[0] === 'guardd') {
    args.shift()
    return {
      mode: 'daemon',
      args,
    }
  }

  if (args[0] === 'monitor-log') {
    args.shift()
    let json = false
    let limit = 50
    let logPath = null
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--json') {
        json = true
      } else if (arg === '--limit') {
        const value = Number(parseFlagValue(args, index))
        if (!Number.isInteger(value) || value < 1) return { mode: 'usage-error' }
        limit = value
        index += 1
      } else if (!logPath) {
        logPath = arg
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'monitor-log',
      json,
      limit,
      logPath,
    }
  }

  if (args[0] === 'profile' && ['add', 'remove'].includes(args[1])) {
    const action = args[1]
    args.splice(0, 2)
    let json = false
    const values = []
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--json') {
        json = true
      } else if (arg === '--profile') {
        profile = parseFlagValue(args, index)
        index += 1
      } else {
        values.push(arg)
      }
    }
    if (values.length !== 2) return { mode: 'usage-error' }
    return {
      mode: 'profile-mutate-array',
      action,
      profile,
      field: values[0],
      value: values[1],
      json,
    }
  }

  if (
    args[0] === 'profile' &&
    ['add-http-rule', 'remove-http-rule'].includes(args[1])
  ) {
    const action = args[1] === 'add-http-rule' ? 'add' : 'remove'
    args.splice(0, 2)
    let json = false
    let host = ''
    let cidr = ''
    const methods = []
    const paths = []
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--json') {
        json = true
      } else if (arg === '--profile') {
        profile = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--host') {
        host = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--cidr') {
        cidr = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--method') {
        methods.push(parseFlagValue(args, index))
        index += 1
      } else if (arg === '--path') {
        paths.push(parseFlagValue(args, index))
        index += 1
      } else {
        return { mode: 'usage-error' }
      }
    }
    if ((!host && !cidr) || (host && cidr)) return { mode: 'usage-error' }
    return {
      mode: 'profile-mutate-http-rule',
      action,
      profile,
      rule: {
        ...(host ? { host } : { cidr }),
        ...(methods.length > 0 ? { methods } : {}),
        ...(paths.length > 0 ? { paths } : {}),
      },
      json,
    }
  }

  if (
    args[0] === 'profile' &&
    ['add-raw-tcp', 'remove-raw-tcp'].includes(args[1])
  ) {
    const action = args[1] === 'add-raw-tcp' ? 'add' : 'remove'
    args.splice(0, 2)
    let json = false
    let host = ''
    let ip = ''
    let port = ''
    let reason = ''
    let resolveAtLaunch = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--json') {
        json = true
      } else if (arg === '--profile') {
        profile = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--host') {
        host = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--ip') {
        ip = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--port') {
        port = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--reason') {
        reason = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--resolve-at-launch') {
        resolveAtLaunch = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    if ((!host && !ip) || (host && ip) || !port) return { mode: 'usage-error' }
    return {
      mode: 'profile-mutate-raw-tcp',
      action,
      profile,
      rule: {
        ...(host ? { host, resolveAtLaunch } : { ip }),
        port,
        ...(reason ? { reason } : {}),
      },
      json,
    }
  }

  if (args[0] === 'profile' && args[1] === 'tls') {
    args.splice(0, 2)
    const action = args.shift()
    if (!['enable', 'disable', 'status'].includes(action)) return { mode: 'usage-error' }
    let json = false
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'profile-tls',
      action,
      profile,
      json,
    }
  }

  if (args[0] === 'profile' && args[1] === 'doctor') {
    args.splice(0, 2)
    let json = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--json') {
        json = true
      } else if (arg === '--profile') {
        profile = parseFlagValue(args, index)
        index += 1
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'profile-doctor',
      profile,
      json,
    }
  }

  if (args[0] === 'install-app' || args[0] === 'install-apps') {
    const installAll = args[0] === 'install-apps'
    args.shift()
    let appName = null
    let targetDir = null
    let force = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--dir') {
        targetDir = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--force') {
        force = true
      } else if (!installAll && !appName && APP_COMMANDS.has(arg)) {
        appName = arg
      } else if (!installAll && !appName && arg === 'all') {
        appName = 'all'
      } else {
        return { mode: 'usage-error' }
      }
    }
    if (installAll && appName) return { mode: 'usage-error' }
    if (!installAll && !appName) return { mode: 'usage-error' }
    return {
      mode: installAll || appName === 'all' ? 'install-apps' : 'install-app',
      appName,
      targetDir,
      force,
    }
  }

  if (args[0] === 'install-monitor') {
    args.shift()
    let targetDir = null
    let force = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--dir') {
        targetDir = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--force') {
        force = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'install-monitor',
      targetDir,
      force,
    }
  }

  if (args[0] === 'ui' || args[0] === 'gui' || args[0] === 'monitor') {
    args.shift()
    let targetDir = null
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--dir') {
        targetDir = parseFlagValue(args, index)
        index += 1
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: 'ui',
      targetDir,
    }
  }

  if (args[0] === 'discover') {
    args.shift()
    let reportPath = null
    let json = false
    while (args.length > 0 && args[0] !== '--') {
      if (args[0] === '--profile') {
        if (!args[1]) return { mode: 'usage-error' }
        profile = args[1]
        args.splice(0, 2)
      } else if (args[0] === '--report') {
        if (!args[1]) return { mode: 'usage-error' }
        reportPath = args[1]
        args.splice(0, 2)
      } else if (args[0] === '--json') {
        json = true
        args.shift()
      } else {
        return { mode: 'usage-error' }
      }
    }
    if (args[0] === '--') args.shift()
    if (args.length === 0) return { mode: 'usage-error' }
    return {
      mode: 'run',
      profile,
      askNetwork: true,
      deepEgress,
      discover: true,
      reportPath,
      json,
      args,
      showPolicyOnly: false,
    }
  }

  if (args[0] === 'diff-profile') {
    args.shift()
    let json = false
    const refs = []
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        refs.push(arg)
      }
    }
    if (refs.length !== 2) return { mode: 'usage-error' }
    return {
      mode: 'diff-profile',
      left: refs[0],
      right: refs[1],
      json,
    }
  }

  if (args[0] === 'network-log') {
    args.shift()
    let json = false
    let logPath = null
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else if (!logPath) {
        logPath = arg
      } else {
        return { mode: 'usage-error' }
      }
    }
    if (!logPath) return { mode: 'usage-error' }
    return {
      mode: 'network-log',
      logPath,
      json,
    }
  }

  if (
    args[0] === 'profiles' ||
    args[0] === 'list-profiles' ||
    (args[0] === 'list' &&
      (args[1] === 'profiles' ||
        args[1] === 'profile' ||
        args[1] === 'templates' ||
        args[1] === 'template' ||
        args[1] === 'domain-presets'))
  ) {
    let listTarget = 'profiles'
    if (args[0] === 'list') {
      listTarget = args[1] === 'domain-presets'
        ? 'domain-presets'
        : args[1] === 'templates' || args[1] === 'template'
          ? 'templates'
          : 'profiles'
      args.splice(0, 2)
    } else {
      args.shift()
    }
    let json = false
    for (const arg of args) {
      if (arg === '--json') {
        json = true
      } else {
        return { mode: 'usage-error' }
      }
    }
    return {
      mode: listTarget === 'domain-presets'
        ? 'list-domain-presets'
        : listTarget === 'templates'
          ? 'list-templates'
          : 'list-profiles',
      json,
    }
  }

  if (args[0] === 'setup') {
    args.shift()
    let binDir = null
    let codeRoot = null
    let includeShims = null
    let force = false
    let yes = false

    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--bin-dir') {
        binDir = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--code-root') {
        codeRoot = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--shims') {
        includeShims = true
      } else if (arg === '--no-shims') {
        includeShims = false
      } else if (arg === '--force') {
        force = true
      } else if (arg === '--yes' || arg === '-y') {
        yes = true
      } else {
        return { mode: 'usage-error' }
      }
    }

    return {
      mode: 'setup',
      profile,
      binDir,
      codeRoot,
      includeShims,
      force,
      yes,
    }
  }

  if (args[0] === 'install') {
    args.shift()
    let binDir = null
    let codeRoot = null
    let includeShims = true
    let force = false

    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--bin-dir') {
        binDir = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--code-root') {
        codeRoot = parseFlagValue(args, index)
        index += 1
      } else if (arg === '--no-shims') {
        includeShims = false
      } else if (arg === '--force') {
        force = true
      } else {
        return { mode: 'usage-error' }
      }
    }

    return {
      mode: 'install',
      profile,
      binDir,
      codeRoot,
      includeShims,
      force,
    }
  }

  if (args[0] === 'init') {
    args.shift()
    let template = 'node-app'
    let force = false

    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === '--force') {
        force = true
      } else if (arg.startsWith('-')) {
        return { mode: 'usage-error' }
      } else if (template === 'node-app') {
        template = arg
      } else {
        return { mode: 'usage-error' }
      }
    }

    return {
      mode: 'init',
      profile,
      template,
      force,
    }
  }

  return {
    mode: 'run',
    profile,
    askNetwork,
    deepEgress,
    args,
    showPolicyOnly: args.length === 0,
  }
}

const pathIncludesDir = (pathValue, dir) => {
  const wanted = safeRealpath(dir)
  return (pathValue || '')
    .split(':')
    .filter(Boolean)
    .some((segment) => safeRealpath(segment) === wanted)
}

const INSTALL_ENTRYPOINT_NAMES = ['guard', 'guard-zoom', 'guard-teams', 'guard-webex']
const INSTALL_SHIM_NAMES = ['node', 'pnpm', 'npm', 'python', 'python3', 'pip', 'pip3']

const inspectInstallLinks = ({ repoRoot, binDir }) => {
  const expectedSource = path.resolve(repoRoot, 'bin/guard')
  return [...INSTALL_ENTRYPOINT_NAMES, ...INSTALL_SHIM_NAMES].map((name) => {
    const target = path.join(binDir, name)
    try {
      const stat = fs.lstatSync(target)
      if (stat.isSymbolicLink()) {
        const source = fs.readlinkSync(target)
        return {
          name,
          target,
          source,
          status: source === expectedSource ? 'installed' : 'other-link',
        }
      }
      return { name, target, source: null, status: 'exists' }
    } catch {
      return { name, target, source: null, status: 'missing' }
    }
  })
}

const formatSetupCurrentValues = ({
  repoRoot,
  selectedBinDir,
  selectedCodeRoot,
  selectedIncludeShims,
  selectedForce,
}) => {
  const managedRoot = collectManagedRootInfo()
  const configPath = resolveGuardConfigPath()
  const userConfig = readGuardUserConfig()
  const links = inspectInstallLinks({ repoRoot, binDir: selectedBinDir })
  const installed = links.filter((link) => link.status === 'installed')
  const entrypointsInstalled = INSTALL_ENTRYPOINT_NAMES.filter((name) =>
    installed.some((link) => link.name === name),
  )
  const shimsInstalled = INSTALL_SHIM_NAMES.filter((name) =>
    installed.some((link) => link.name === name),
  )
  return [
    'Current Guard Setup',
    `  config: ${configPath || '-'}`,
    `  managed root: ${managedRoot.root}`,
    `  managed root source: ${managedRoot.source}`,
    `  install dir: ${userConfig.installBinDir || selectedBinDir}`,
    `  install dir source: ${
      process.env.GUARD_INSTALL_BIN_DIR
        ? 'GUARD_INSTALL_BIN_DIR'
        : userConfig.installBinDir
          ? configPath || 'user config'
          : 'default'
    }`,
    `  include shims: ${
      typeof userConfig.includeShims === 'boolean'
        ? userConfig.includeShims ? 'yes' : 'no'
        : 'default yes'
    }`,
    `  install dir on PATH: ${pathIncludesDir(process.env.PATH || '', selectedBinDir) ? 'yes' : 'no'}`,
    `  installed entrypoints: ${entrypointsInstalled.length > 0 ? entrypointsInstalled.join(' ') : '-'}`,
    `  installed shims: ${shimsInstalled.length > 0 ? shimsInstalled.join(' ') : '-'}`,
    '',
    'Setup Selections',
    `  managed root: ${selectedCodeRoot}`,
    `  install dir: ${selectedBinDir}`,
    `  install shims: ${selectedIncludeShims ? 'yes' : 'no'}`,
    `  replace existing links: ${selectedForce ? 'yes' : 'no'}`,
  ]
}

const installGuardLinks = ({ repoRoot, includeShims, force, binDir = null, codeRoot = null }) => {
  const resolvedBinDir = binDir ? path.resolve(binDir) : resolveInstallBinDir()
  fs.mkdirSync(resolvedBinDir, { recursive: true })
  const configuredRoot = codeRoot
    ? path.resolve(expandHome(codeRoot))
    : resolveManagedRoot()
  const userConfig = writeGuardUserConfig({
    codeRoot: configuredRoot,
    installBinDir: resolvedBinDir,
    includeShims,
  })

  const links = [
    ...INSTALL_ENTRYPOINT_NAMES.map((name) => [name, path.resolve(repoRoot, 'bin/guard')]),
  ]
  if (includeShims) {
    for (const tool of INSTALL_SHIM_NAMES) {
      links.push([tool, path.resolve(repoRoot, 'bin/guard')])
    }
  }

  const results = []
  for (const [name, source] of links) {
    const target = path.join(resolvedBinDir, name)
    const status = linkTarget(target, source, { force })
    results.push({ name, target, source, status })
  }

  const lines = [
    `Installed guard links in ${resolvedBinDir}`,
    `Configured managed root: ${configuredRoot}`,
    `Wrote user config: ${userConfig.configPath}`,
    ...results.map(({ name, status, source }) => `  ${name}: ${status} -> ${source}`),
  ]
  if (!pathIncludesDir(process.env.PATH || '', resolvedBinDir)) {
    lines.push(`PATH warning: add ${resolvedBinDir} to PATH for installed guard commands`)
  }

  return {
    resolvedBinDir,
    configuredRoot,
    configPath: userConfig.configPath,
    results,
    lines,
  }
}

const runInstall = ({ repoRoot, includeShims, force, binDir = null, codeRoot = null }) => {
  const install = installGuardLinks({
    repoRoot,
    includeShims,
    force,
    binDir,
    codeRoot,
  })
  const lines = install.lines
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(0)
}

const promptText = async (rl, label, defaultValue) => {
  const reply = await rl.question(`${label} [${defaultValue}]: `)
  return reply.trim() || defaultValue
}

const promptBoolean = async (rl, label, defaultValue) => {
  const suffix = defaultValue ? 'Y/n' : 'y/N'
  const reply = (await rl.question(`${label} [${suffix}]: `)).trim().toLowerCase()
  if (!reply) return defaultValue
  return reply === 'y' || reply === 'yes'
}

const runSetup = async ({
  repoRoot,
  includeShims,
  force,
  binDir = null,
  codeRoot = null,
  yes = false,
}) => {
  let selectedBinDir = binDir ? path.resolve(expandHome(binDir)) : resolveInstallBinDir()
  let selectedCodeRoot = codeRoot ? path.resolve(expandHome(codeRoot)) : resolveManagedRoot()
  const userConfig = readGuardUserConfig()
  let selectedIncludeShims =
    includeShims !== null && includeShims !== undefined
      ? includeShims
      : typeof userConfig.includeShims === 'boolean'
        ? userConfig.includeShims
        : true
  let selectedForce = force

  const writeCurrentValues = () => {
    process.stdout.write(
      `${formatSetupCurrentValues({
        repoRoot,
        selectedBinDir,
        selectedCodeRoot,
        selectedIncludeShims,
        selectedForce,
      }).join('\n')}\n\n`,
    )
  }

  const interactive = process.stdin.isTTY && process.stderr.isTTY && !yes
  if (interactive) {
    process.stdout.write('Guard Setup\n\n')
    writeCurrentValues()
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
    })
    try {
      selectedCodeRoot = path.resolve(expandHome(await promptText(
        rl,
        'Managed code root',
        selectedCodeRoot,
      )))
      selectedBinDir = path.resolve(expandHome(await promptText(
        rl,
        'Install links into',
        selectedBinDir,
      )))
      selectedIncludeShims = await promptBoolean(
        rl,
        'Install PATH shims for node, pnpm, npm, python, pip',
        selectedIncludeShims,
      )
      selectedForce = await promptBoolean(rl, 'Replace existing links if needed', selectedForce)
      const proceed = await promptBoolean(rl, 'Apply this setup', true)
      if (!proceed) {
        process.stdout.write('Setup cancelled\n')
        process.exit(130)
      }
    } finally {
      rl.close()
    }
  } else if (!yes) {
    process.stdout.write('Guard Setup: non-interactive shell, using defaults and provided flags\n')
    writeCurrentValues()
  } else {
    writeCurrentValues()
  }

  const install = installGuardLinks({
    repoRoot,
    includeShims: selectedIncludeShims,
    force: selectedForce,
    binDir: selectedBinDir,
    codeRoot: selectedCodeRoot,
  })

  const lines = [
    'Guard setup complete',
    ...install.lines,
    '',
    'Next steps:',
    `  1. Ensure ${install.resolvedBinDir} is on PATH`,
    '  2. Run: guard doctor',
    `  3. In a project under ${install.configuredRoot}: guard init`,
  ]
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(0)
}

const runInit = ({ repoRoot, cwd, template, force }) => {
  const { templatePath, targetPath } = createProjectFromTemplate({
    repoRoot,
    cwd,
    template,
    force,
  })
  process.stdout.write(
    `Created ${targetPath} from ${templatePath}\n`,
  )
  process.exit(0)
}

const runDoctor = ({
  repoRoot,
  invokedPath,
  profile,
  cwd,
  json,
  tool,
}) => {
  const info = collectDoctorInfo({
    repoRoot,
    invokedPath,
    cwd,
    profile,
    targetTool: tool,
  })

  if (json) {
    emit(process.stdout, JSON.stringify(info, null, 2))
  } else {
    process.stdout.write(formatDoctorText(info))
  }
  process.exit(0)
}

const runAudit = ({ repoRoot, profile, cwd, json }) => {
  const { resolved, cfg } = loadExpandedProfile({ repoRoot, cwd, profile })
  const audit = auditExpandedPolicy({
    cfg,
    configPath: resolved.config,
    profile,
    source: resolved.source,
    cwd,
  })

  if (json) {
    emit(process.stdout, JSON.stringify(audit, null, 2))
  } else {
    process.stdout.write(formatAuditText(audit))
  }
  process.exit(0)
}

const buildAppSummary = ({ repoRoot, cwd, profile }) => {
  const { resolved, raw, cfg } = loadExpandedProfile({ repoRoot, cwd, profile })
  const metadata = raw.metadata || {}
  const network = cfg.network || {}
  const fsCfg = cfg.filesystem || {}
  const audit = auditExpandedPolicy({
    cfg,
    configPath: resolved.config,
    profile,
    source: resolved.source,
    cwd,
  })

  return {
    profile,
    source: resolved.source,
    configPath: resolved.config,
    description: metadata.description || '',
    risk: metadata.risk || 'unknown',
    status: metadata.status || 'unknown',
    launcher: metadata.launcher || getProfileLauncher(profile),
    appBundle: metadata.appBundle || null,
    network: {
      mode: getNetworkMode(cfg),
      allowedDomains: Array.isArray(network.allowedDomains)
        ? network.allowedDomains
        : [],
      allowedRawTcp: Array.isArray(network.allowedRawTcp)
        ? network.allowedRawTcp
        : [],
      httpRules: Array.isArray(network.httpRules) ? network.httpRules : [],
      deniedDomains: Array.isArray(network.deniedDomains)
        ? network.deniedDomains
        : [],
      deniedDomainPresets: Array.isArray(raw.network?.deniedDomainPresets)
        ? raw.network.deniedDomainPresets
        : [],
      tlsInspection: normalizeTlsInspection(network),
      allowLocalBinding: network.allowLocalBinding === true,
      allowLoopbackConnections: network.allowLoopbackConnections === true,
      allowLoopbackHighPorts: network.allowLoopbackHighPorts === true,
      allowLoopbackListeningHighPorts: isLoopbackListeningHighPortsEnabled(
        network.allowLoopbackListeningHighPorts,
      ),
      allowLoopbackListeningHighPortProcesses: normalizeListeningHighPortProcesses(
        network.allowLoopbackListeningHighPorts,
      ) || [],
      allowLoopbackPorts: Array.isArray(network.allowLoopbackPorts)
        ? network.allowLoopbackPorts
        : [],
    },
    filesystem: {
      allowRead: Array.isArray(fsCfg.allowRead) ? fsCfg.allowRead : [],
      denyRead: Array.isArray(fsCfg.denyRead) ? fsCfg.denyRead : [],
      allowWrite: Array.isArray(fsCfg.allowWrite) ? fsCfg.allowWrite : [],
      denyWrite: Array.isArray(fsCfg.denyWrite) ? fsCfg.denyWrite : [],
    },
    findings: audit.findings,
  }
}

const formatAppSummaryText = (summary) => {
  const lines = [
    `Guard App Summary: ${summary.profile}`,
    `description: ${summary.description || '-'}`,
    `status: ${summary.status}`,
    `risk: ${summary.risk}`,
    `app bundle: ${summary.appBundle || '-'}`,
    `launcher: ${summary.launcher || '-'}`,
    `network: ${summary.network.mode}`,
    `loopback: ${
      summary.network.allowLoopbackConnections
        ? 'all'
        : [
            summary.network.allowLoopbackHighPorts ? 'high' : null,
            summary.network.allowLoopbackListeningHighPorts
              ? summary.network.allowLoopbackListeningHighPortProcesses.length > 0
                ? `listening-high:${summary.network.allowLoopbackListeningHighPortProcesses.join(',')}`
                : 'listening-high'
              : null,
            ...summary.network.allowLoopbackPorts,
          ]
            .filter((value) => value !== null)
            .join(' ') || '-'
    }`,
    `allowed domains: ${summary.network.allowedDomains.length > 0 ? summary.network.allowedDomains.join(' ') : '-'}`,
    `raw TCP: ${summary.network.allowedRawTcp.length}`,
    `http rules: ${summary.network.httpRules.length}`,
    `TLS inspection: ${summary.network.tlsInspection.enabled ? summary.network.tlsInspection.mode : 'off'}`,
    `denied domains: ${summary.network.deniedDomains.length > 0 ? summary.network.deniedDomains.join(' ') : '-'}`,
    `read deny: ${summary.filesystem.denyRead.join(' ') || '-'}`,
    `write deny: ${summary.filesystem.denyWrite.join(' ') || '-'}`,
  ]
  if (summary.findings.length === 0) {
    lines.push('warnings: none')
  } else {
    lines.push('warnings:')
    for (const finding of summary.findings) {
      lines.push(`  [${finding.severity}] ${finding.id}: ${finding.message}`)
    }
  }
  return `${lines.join('\n')}\n`
}

const runAppSummary = ({ repoRoot, profile, cwd, json }) => {
  const summary = buildAppSummary({ repoRoot, cwd, profile })
  if (json) {
    emit(process.stdout, JSON.stringify(summary, null, 2))
  } else {
    process.stdout.write(formatAppSummaryText(summary))
  }
  process.exit(0)
}

const xmlEscape = (value) =>
  String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')

const runSync = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  })
  if (result.error) {
    throw result.error
  }
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed\n${result.stderr || result.stdout || ''}`,
    )
  }
  return result
}

const fileMtimeMs = (filePath) => {
  try {
    return fs.statSync(filePath).mtimeMs
  } catch {
    return 0
  }
}

const nativeSourcePath = (repoRoot) =>
  path.resolve(repoRoot, 'native/macos-launcher/GuardAppLauncher.swift')

const buildNativeLauncherBinary = (repoRoot) => {
  const source = nativeSourcePath(repoRoot)
  if (!fs.existsSync(source)) {
    throw new Error(`native launcher source missing: ${source}`)
  }
  const buildDir = path.resolve(repoRoot, 'native/macos-launcher/.build')
  const output = path.join(buildDir, 'GuardAppLauncher')
  fs.mkdirSync(buildDir, { recursive: true })
  if (fs.existsSync(output) && fileMtimeMs(output) >= fileMtimeMs(source)) {
    return output
  }
  runSync('/usr/bin/xcrun', [
    'swiftc',
    '-O',
    '-framework',
    'AppKit',
    source,
    '-o',
    output,
  ])
  fs.chmodSync(output, 0o755)
  return output
}

const buildNativeMonitorBinary = (repoRoot) => {
  const source = nativeSourcePath(repoRoot)
  if (!fs.existsSync(source)) {
    throw new Error(`native monitor source missing: ${source}`)
  }
  const buildDir = path.resolve(repoRoot, 'native/macos-launcher/.build')
  const output = path.join(buildDir, 'GuardMonitor')
  fs.mkdirSync(buildDir, { recursive: true })
  if (fs.existsSync(output) && fileMtimeMs(output) >= fileMtimeMs(source)) {
    return output
  }
  runSync('/usr/bin/xcrun', [
    'swiftc',
    '-O',
    '-framework',
    'AppKit',
    source,
    '-o',
    output,
  ])
  fs.chmodSync(output, 0o755)
  return output
}

const createNativeLauncherInfoPlist = ({ app, executableName }) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>${xmlEscape(`Guard ${app.label}`)}</string>
  <key>CFBundleExecutable</key>
  <string>${xmlEscape(executableName)}</string>
  <key>CFBundleIconFile</key>
  <string>GuardAppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>${xmlEscape(app.bundleIdentifier)}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${xmlEscape(`Guard ${app.label}`)}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
`

const nativeLauncherConfig = ({ app, guardPath }) => ({
  mode: 'launcher',
  profile: app.profile,
  displayName: app.label,
  guardPath,
  bundleIdentifier: app.bundleIdentifier,
})

const nativeMonitorConfig = ({ guardPath, eventLogPath }) => ({
  mode: 'monitor',
  profile: 'guard',
  displayName: 'Monitor',
  guardPath,
  bundleIdentifier: 'dev.guard.monitor',
  eventLogPath,
})

const nativeMonitorBuildStamp = ({ repoRoot, guardPath, eventLogPath }) => ({
  source: nativeSourcePath(repoRoot),
  sourceMtimeMs: fileMtimeMs(nativeSourcePath(repoRoot)),
  guardPath,
  eventLogPath,
  version: 4,
})

const defaultNativeAppDir = () => {
  if (!process.env.HOME) {
    throw new Error('HOME is required to resolve the default app install directory')
  }
  return path.join(process.env.HOME, 'Applications')
}

const resolveNativeAppInstallDir = (targetDir) =>
  targetDir ? path.resolve(targetDir) : defaultNativeAppDir()

const getNativeAppPath = ({ app, installDir }) =>
  path.join(installDir, `Guard ${app.label}.app`)

const createNativeMonitorInfoPlist = ({ executableName }) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>Guard Monitor</string>
  <key>CFBundleExecutable</key>
  <string>${xmlEscape(executableName)}</string>
  <key>CFBundleIconFile</key>
  <string>GuardAppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>dev.guard.monitor</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Guard Monitor</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
`

const installNativeApp = ({
  repoRoot,
  appName,
  targetDir,
  force,
  launcherBinary = null,
}) => {
  const app = APP_LAUNCHERS[`guard-${appName}`]
  if (!app) {
    throw new Error(`unknown app launcher: ${appName}`)
  }

  const resolvedLauncherBinary = launcherBinary || buildNativeLauncherBinary(repoRoot)
  const installDir = resolveNativeAppInstallDir(targetDir)
  const appPath = getNativeAppPath({ app, installDir })
  const contentsDir = path.join(appPath, 'Contents')
  const macosDir = path.join(contentsDir, 'MacOS')
  const resourcesDir = path.join(contentsDir, 'Resources')
  const executableName = 'GuardAppLauncher'
  const guardPath = path.resolve(repoRoot, 'bin/guard')

  if (fs.existsSync(appPath)) {
    if (!force) {
      throw new Error(`refusing to replace existing app without --force: ${appPath}`)
    }
    fs.rmSync(appPath, { recursive: true, force: true })
  }

  fs.mkdirSync(macosDir, { recursive: true })
  fs.mkdirSync(resourcesDir, { recursive: true })
  fs.copyFileSync(resolvedLauncherBinary, path.join(macosDir, executableName))
  fs.chmodSync(path.join(macosDir, executableName), 0o755)
  if (fs.existsSync(app.icon)) {
    fs.copyFileSync(app.icon, path.join(resourcesDir, 'GuardAppIcon.icns'))
  }
  fs.writeFileSync(
    path.join(contentsDir, 'Info.plist'),
    createNativeLauncherInfoPlist({ app, executableName }),
  )
  fs.writeFileSync(
    path.join(resourcesDir, 'GuardAppConfig.json'),
    `${JSON.stringify(nativeLauncherConfig({ app, guardPath }), null, 2)}\n`,
  )

  runSync('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', appPath])

  return {
    appName,
    label: app.label,
    path: appPath,
    profile: app.profile,
    icon: fs.existsSync(app.icon) ? app.icon : null,
    guardPath,
  }
}

const runInstallApp = ({ repoRoot, appName, targetDir, force }) => {
  const installed = installNativeApp({ repoRoot, appName, targetDir, force })
  const lines = [
    `Installed Guard ${installed.label}.app`,
    `path: ${installed.path}`,
    `profile: ${installed.profile}`,
    `guard: ${installed.guardPath}`,
    `icon: ${installed.icon || 'default'}`,
  ]
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(0)
}

const installNativeApps = ({ repoRoot, targetDir, force }) => {
  const appNames = [...APP_COMMANDS]
  const installDir = resolveNativeAppInstallDir(targetDir)
  fs.mkdirSync(installDir, { recursive: true })

  for (const appName of appNames) {
    const app = APP_LAUNCHERS[`guard-${appName}`]
    const appPath = getNativeAppPath({ app, installDir })
    if (fs.existsSync(appPath) && !force) {
      throw new Error(`refusing to replace existing app without --force: ${appPath}`)
    }
  }

  const launcherBinary = buildNativeLauncherBinary(repoRoot)
  return appNames.map((appName) =>
    installNativeApp({
      repoRoot,
      appName,
      targetDir: installDir,
      force,
      launcherBinary,
    }),
  )
}

const runInstallApps = ({ repoRoot, targetDir, force }) => {
  const installedApps = installNativeApps({ repoRoot, targetDir, force })
  const lines = [
    `Installed ${installedApps.length} Guard native apps`,
    ...installedApps.map(
      (installed) =>
        `  Guard ${installed.label}.app: ${installed.path} profile=${installed.profile} icon=${installed.icon || 'default'}`,
    ),
  ]
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(0)
}

const readJsonOrNull = (filePath) => {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'))
  } catch {
    return null
  }
}

const pngCrcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
  }
  return value >>> 0
})

const pngCrc = (type, data) => {
  let crc = 0xffffffff
  for (const byte of Buffer.from(type, 'ascii')) {
    crc = pngCrcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }
  for (const byte of data) {
    crc = pngCrcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

const pngChunk = (type, data) => {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(data.length, 0)
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(pngCrc(type, data), 0)
  return Buffer.concat([length, Buffer.from(type, 'ascii'), data, crc])
}

const writePngRgba = (filePath, size, pixels) => {
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(size, 0)
  ihdr.writeUInt32BE(size, 4)
  ihdr[8] = 8
  ihdr[9] = 6
  const stride = size * 4
  const raw = Buffer.alloc((stride + 1) * size)
  for (let y = 0; y < size; y += 1) {
    const rowStart = y * (stride + 1)
    raw[rowStart] = 0
    pixels.copy(raw, rowStart + 1, y * stride, (y + 1) * stride)
  }
  fs.writeFileSync(
    filePath,
    Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      pngChunk('IHDR', ihdr),
      pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
      pngChunk('IEND', Buffer.alloc(0)),
    ]),
  )
}

const writePngIcon = (filePath, size) => {
  const clamp = (value) => Math.max(0, Math.min(255, Math.round(value)))
  const mix = (a, b, t) => a + (b - a) * t
  const smoothstep = (edge0, edge1, x) => {
    const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0)))
    return t * t * (3 - 2 * t)
  }
  const colorMix = (left, right, t) => left.map((value, index) => mix(value, right[index], t))
  const over = (base, layer) => {
    const alpha = Math.max(0, Math.min(1, layer[3]))
    return [
      mix(base[0], layer[0], alpha),
      mix(base[1], layer[1], alpha),
      mix(base[2], layer[2], alpha),
      alpha + base[3] * (1 - alpha),
    ]
  }
  const roundedRectAlpha = (x, y, left, top, width, height, radius) => {
    const px = x - (left + width / 2)
    const py = y - (top + height / 2)
    const qx = Math.abs(px) - width / 2 + radius
    const qy = Math.abs(py) - height / 2 + radius
    const outside = Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) - radius
    return 1 - smoothstep(-0.7, 0.7, outside)
  }
  const pixels = Buffer.alloc(size * size * 4)
  const samples = size < 128 ? 6 : 4
  const tile = {
    x: size * 0.13,
    y: size * 0.12,
    width: size * 0.74,
    height: size * 0.74,
    radius: size * 0.205,
  }
  const barCount = 5
  const barWidth = size * 0.107
  const barGap = size * 0.018
  const groupWidth = barCount * barWidth + (barCount - 1) * barGap
  const groupLeft = size / 2 - groupWidth / 2
  const barBase = size * 0.685
  const barTops = [0.462, 0.36, 0.265, 0.36, 0.462].map((value) => value * size)
  const render = (x, y) => {
    let color = [0, 0, 0, 0]
    const shadow = roundedRectAlpha(
      x,
      y,
      tile.x - size * 0.008,
      tile.y + size * 0.035,
      tile.width + size * 0.016,
      tile.height + size * 0.012,
      tile.radius + size * 0.01,
    )
    if (shadow > 0) {
      color = over(color, [0, 0, 0, shadow * 0.36])
    }

    const bgT = Math.max(0, Math.min(1, (y - tile.y) / tile.height))
    const tileAlpha = roundedRectAlpha(x, y, tile.x, tile.y, tile.width, tile.height, tile.radius)
    if (tileAlpha > 0) {
      const dx = (x - size / 2) / size
      const dy = (y - size * 0.48) / size
      const glow = Math.max(0, 1 - Math.hypot(dx, dy) * 2.25)
      const tileColor = colorMix([48, 53, 76], [13, 16, 28], bgT)
      const liftedTileColor = [
        tileColor[0] + 24 * glow,
        tileColor[1] + 12 * glow,
        tileColor[2] + 34 * glow,
      ]
      color = over(color, [...liftedTileColor, tileAlpha])
    }

    const borderOuter = roundedRectAlpha(
      x,
      y,
      tile.x - size * 0.012,
      tile.y - size * 0.012,
      tile.width + size * 0.024,
      tile.height + size * 0.024,
      tile.radius + size * 0.018,
    )
    if (borderOuter > tileAlpha) {
      color = over(color, [99, 104, 124, (borderOuter - tileAlpha) * 0.9])
    }

    const shine = roundedRectAlpha(
      x,
      y,
      tile.x + size * 0.035,
      tile.y + size * 0.035,
      tile.width - size * 0.07,
      tile.height * 0.42,
      tile.radius * 0.72,
    )
    if (shine > 0 && y < size * 0.43) {
      color = over(color, [110, 118, 150, shine * 0.22])
    }

    for (let index = 0; index < barCount; index += 1) {
      const barLeft = groupLeft + index * (barWidth + barGap)
      const top = barTops[index]
      const upperHeight = size * 0.25
      const lowerTop = top + upperHeight * 0.54
      const upperAlpha = roundedRectAlpha(x, y, barLeft, top, barWidth, upperHeight, barWidth * 0.48)
      if (upperAlpha > 0) {
        const upper = colorMix([255, 50, 250], [185, 55, 230], Math.max(0, Math.min(1, (y - top) / upperHeight)))
        color = over(color, [...upper, upperAlpha])
      }
      const lowerHeight = barBase - lowerTop
      const lowerAlpha = roundedRectAlpha(x, y, barLeft, lowerTop, barWidth, lowerHeight, barWidth * 0.48)
      if (lowerAlpha > 0) {
        const lower = colorMix([44, 218, 255], [0, 143, 225], Math.max(0, Math.min(1, (y - lowerTop) / lowerHeight)))
        color = over(color, [...lower, lowerAlpha])
      }
    }

    const markShadow = roundedRectAlpha(
      x,
      y,
      groupLeft - size * 0.035,
      size * 0.7,
      groupWidth + size * 0.07,
      size * 0.045,
      size * 0.03,
    )
    if (markShadow > 0) {
      color = over(color, [3, 6, 13, markShadow * 0.16])
    }
    return color
  }

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let r = 0
      let g = 0
      let b = 0
      let a = 0
      for (let sy = 0; sy < samples; sy += 1) {
        for (let sx = 0; sx < samples; sx += 1) {
          const [rr, gg, bb, aa] = render(x + (sx + 0.5) / samples, y + (sy + 0.5) / samples)
          r += rr
          g += gg
          b += bb
          a += aa
        }
      }
      const sampleCount = samples * samples
      const offset = (y * size + x) * 4
      pixels[offset] = clamp(r / sampleCount)
      pixels[offset + 1] = clamp(g / sampleCount)
      pixels[offset + 2] = clamp(b / sampleCount)
      pixels[offset + 3] = clamp((a / sampleCount) * 255)
    }
  }
  writePngRgba(filePath, size, pixels)
}

const generateMonitorIcon = (resourcesDir) => {
  const iconset = path.join(resourcesDir, 'GuardAppIcon.iconset')
  fs.rmSync(iconset, { recursive: true, force: true })
  fs.mkdirSync(iconset, { recursive: true })
  const specs = [
    ['icon_16x16.png', 16],
    ['icon_16x16@2x.png', 32],
    ['icon_32x32.png', 32],
    ['icon_32x32@2x.png', 64],
    ['icon_128x128.png', 128],
    ['icon_128x128@2x.png', 256],
    ['icon_256x256.png', 256],
    ['icon_256x256@2x.png', 512],
    ['icon_512x512.png', 512],
    ['icon_512x512@2x.png', 1024],
  ]
  for (const [name, size] of specs) {
    const png = path.join(iconset, name)
    writePngIcon(png, size)
  }
  runSync('/usr/bin/iconutil', ['-c', 'icns', iconset, '-o', path.join(resourcesDir, 'GuardAppIcon.icns')])
  fs.rmSync(iconset, { recursive: true, force: true })
}

const copyMonitorIcon = (resourcesDir) => {
  try {
    generateMonitorIcon(resourcesDir)
  } catch {
    const systemIcon = '/System/Library/UserNotifications/Bundles/com.apple.PrivacyProxyNotifications.bundle/Contents/Resources/PrivacyProxy.icns'
    if (fs.existsSync(systemIcon)) {
      fs.copyFileSync(systemIcon, path.join(resourcesDir, 'GuardAppIcon.icns'))
    }
  }
}

const monitorAppCurrent = ({ appPath, repoRoot, guardPath, eventLogPath }) => {
  const stampPath = path.join(appPath, 'Contents', 'Resources', 'GuardBuildStamp.json')
  const executablePath = path.join(appPath, 'Contents', 'MacOS', 'GuardMonitor')
  const iconPath = path.join(appPath, 'Contents', 'Resources', 'GuardAppIcon.icns')
  const expected = nativeMonitorBuildStamp({ repoRoot, guardPath, eventLogPath })
  const actual = readJsonOrNull(stampPath)
  return Boolean(
    actual
      && actual.version === expected.version
      && actual.sourceMtimeMs === expected.sourceMtimeMs
      && actual.guardPath === expected.guardPath
      && actual.eventLogPath === expected.eventLogPath
      && fs.existsSync(executablePath)
      && fs.existsSync(iconPath),
  )
}

const installNativeMonitor = ({ repoRoot, targetDir, force, reuseExisting = false }) => {
  const installDir = resolveNativeAppInstallDir(targetDir)
  const appPath = path.join(installDir, 'Guard Monitor.app')
  const contentsDir = path.join(appPath, 'Contents')
  const macosDir = path.join(contentsDir, 'MacOS')
  const resourcesDir = path.join(contentsDir, 'Resources')
  const executableName = 'GuardMonitor'
  const guardPath = path.resolve(repoRoot, 'bin/guard')
  const eventLogPath = resolveGuardEventLogPath()
  const stamp = nativeMonitorBuildStamp({ repoRoot, guardPath, eventLogPath })

  if (reuseExisting && fs.existsSync(appPath) && monitorAppCurrent({ appPath, repoRoot, guardPath, eventLogPath })) {
    return { path: appPath, guardPath, eventLogPath, reused: true }
  }

  const monitorBinary = buildNativeMonitorBinary(repoRoot)

  if (fs.existsSync(appPath)) {
    if (!force) {
      throw new Error(`refusing to replace existing app without --force: ${appPath}`)
    }
    fs.rmSync(appPath, { recursive: true, force: true })
  }

  fs.mkdirSync(macosDir, { recursive: true })
  fs.mkdirSync(resourcesDir, { recursive: true })
  fs.copyFileSync(monitorBinary, path.join(macosDir, executableName))
  fs.chmodSync(path.join(macosDir, executableName), 0o755)
  copyMonitorIcon(resourcesDir)
  fs.writeFileSync(
    path.join(contentsDir, 'Info.plist'),
    createNativeMonitorInfoPlist({ executableName }),
  )
  fs.writeFileSync(
    path.join(resourcesDir, 'GuardAppConfig.json'),
    `${JSON.stringify(nativeMonitorConfig({ guardPath, eventLogPath }), null, 2)}\n`,
  )
  fs.writeFileSync(
    path.join(resourcesDir, 'GuardBuildStamp.json'),
    `${JSON.stringify(stamp, null, 2)}\n`,
  )
  runSync('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', appPath])
  return { path: appPath, guardPath, eventLogPath, reused: false }
}

const runInstallMonitor = ({ repoRoot, targetDir, force }) => {
  const installed = installNativeMonitor({ repoRoot, targetDir, force })
  const lines = [
    'Installed Guard Monitor.app',
    `path: ${installed.path}`,
    `guard: ${installed.guardPath}`,
    `events: ${installed.eventLogPath}`,
  ]
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(0)
}

const runUi = ({ repoRoot, targetDir }) => {
  const installed = installNativeMonitor({ repoRoot, targetDir, force: true, reuseExisting: true })
  runSync('/usr/bin/open', [installed.path])
  const lines = [
    installed.reused ? 'Opened Guard Monitor.app' : 'Installed and opened Guard Monitor.app',
    `path: ${installed.path}`,
    `guard: ${installed.guardPath}`,
    `events: ${installed.eventLogPath}`,
  ]
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(0)
}

const resolveMutableProjectProfile = ({ cwd, profile }) => {
  const resolved = findNearestProfile(cwd, profile)
  if (!resolved) {
    throw new Error(
      `no project .guard/${profile}.json found above ${cwd}; run "guard init" first`,
    )
  }
  return resolved
}

const formatProfileMutationText = (result) => {
  const action = result.changed ? result.action : `${result.action} (no change)`
  const target = result.field === 'network.httpRules' || result.field === 'network.allowedRawTcp'
    ? stableProfileJson(result.value)
    : String(result.value)
  return [
    `Guard profile ${action}`,
    `profile: ${result.profile}`,
    `config: ${result.configPath}`,
    `field: ${result.field}`,
    `value: ${target}`,
  ].join('\n') + '\n'
}

const emitProfileMutationResult = (result, json) => {
  if (json) {
    emit(process.stdout, JSON.stringify(result, null, 2))
  } else {
    process.stdout.write(formatProfileMutationText(result))
  }
  process.exit(0)
}

const runProfileTls = ({ cwd, profile, action, json }) => {
  const resolved = resolveMutableProjectProfile({ cwd, profile })
  const cfg = readJsonFile(resolved.config)
  const before = normalizeTlsInspection(cfg.network)

  let changed = false
  let after = before
  if (action === 'enable' || action === 'disable') {
    const result = mutateTlsConfig({ cfg, enabled: action === 'enable' })
    changed = result.changed
    after = normalizeTlsInspection(cfg.network)
    if (changed) writeJsonFile(resolved.config, cfg)
  }

  const result = {
    action,
    changed,
    profile,
    configPath: resolved.config,
    before,
    after,
  }

  if (json) {
    emit(process.stdout, JSON.stringify(result, null, 2))
  } else {
    process.stdout.write(formatTlsInspectionText({
      profile,
      configPath: resolved.config,
      networkBackend: cfg.network.backend || 'guard',
      tlsInspection: result.after,
    }))
  }
  process.exit(0)
}

const runProfileMutateArray = ({ cwd, profile, field, value, action, json }) => {
  if (!MUTABLE_PROFILE_ARRAY_FIELDS.has(field)) {
    throw new Error(`unsupported profile field: ${field}`)
  }
  const resolved = resolveMutableProjectProfile({ cwd, profile })
  const cfg = readJsonFile(resolved.config)
  const result = mutateArrayRuleConfig({ cfg, field, value, action, source: 'cli' })
  if (result.changed) writeJsonFile(resolved.config, cfg)
  emitProfileMutationResult({
    ...result,
    profile,
    configPath: resolved.config,
  }, json)
}

const runProfileMutateHttpRule = ({ cwd, profile, rule, action, json }) => {
  const resolved = resolveMutableProjectProfile({ cwd, profile })
  const cfg = readJsonFile(resolved.config)
  const result = mutateHttpRuleConfig({ cfg, rule, action, source: 'cli' })
  if (result.changed) writeJsonFile(resolved.config, cfg)
  emitProfileMutationResult({
    ...result,
    profile,
    configPath: resolved.config,
  }, json)
}

const runProfileMutateRawTcpRule = ({ cwd, profile, rule, action, json }) => {
  const resolved = resolveMutableProjectProfile({ cwd, profile })
  const cfg = readJsonFile(resolved.config)
  const result = mutateRawTcpRuleConfig({ cfg, rule, action, source: 'cli' })
  if (result.changed) writeJsonFile(resolved.config, cfg)
  emitProfileMutationResult({
    ...result,
    profile,
    configPath: resolved.config,
  }, json)
}

const runProfileDoctor = ({ repoRoot, profile, cwd, json }) => {
  const { resolved, raw, cfg } = loadExpandedProfile({ repoRoot, cwd, profile })
  const audit = auditExpandedPolicy({
    cfg,
    configPath: resolved.config,
    profile,
    source: resolved.source,
    cwd,
  })
  const doctor = collectProfileDoctor({
    raw,
    cfg,
    audit,
    configPath: resolved.config,
    profile,
    source: resolved.source,
  })

  if (json) {
    emit(process.stdout, JSON.stringify(doctor, null, 2))
  } else {
    process.stdout.write(formatProfileDoctorText(doctor))
  }
  process.exit(0)
}

const runListProfiles = ({ repoRoot, json }) => {
  const profiles = listBuiltInProfiles(repoRoot)
  if (json) {
    emit(process.stdout, JSON.stringify({ profiles }, null, 2))
  } else {
    process.stdout.write(formatBuiltInProfilesText(profiles))
  }
  process.exit(0)
}

const runListTemplates = ({ repoRoot, json }) => {
  const templates = listProjectTemplates(repoRoot)
  if (json) {
    emit(process.stdout, JSON.stringify({ templates }, null, 2))
  } else {
    process.stdout.write(formatProjectTemplatesText(templates))
  }
  process.exit(0)
}

const runListDomainPresets = ({ json }) => {
  if (json) {
    emit(process.stdout, JSON.stringify({ presets: DENIED_DOMAIN_PRESETS }, null, 2))
  } else {
    process.stdout.write(formatDomainPresetsText())
  }
  process.exit(0)
}

const runDaemon = async ({ repoRoot, args }) => {
  await exitLikeChild(process.execPath, [
    path.resolve(repoRoot, 'daemon/guardd.mjs'),
    ...args,
  ], {
    env: {
      ...process.env,
      GUARD_SHIM_BYPASS: '1',
    },
  })
}

const resolveProfileRef = ({ repoRoot, ref }) => {
  const pathRef = path.resolve(ref)
  const profilePath = fs.existsSync(pathRef)
    ? pathRef
    : path.resolve(repoRoot, 'profiles', `${ref}.json`)
  if (!fs.existsSync(profilePath)) {
    throw new Error(`unknown profile: ${ref}`)
  }
  return {
    ref,
    path: profilePath,
    config: loadProfileConfig({ repoRoot, configPath: profilePath }),
  }
}

const getAtPath = (value, dottedPath) =>
  dottedPath.split('.').reduce((current, key) => current?.[key], value)

const diffArray = (left = [], right = []) => {
  const leftValues = Array.isArray(left) ? left : []
  const rightValues = Array.isArray(right) ? right : []
  return {
    added: rightValues.filter((value) => !leftValues.includes(value)),
    removed: leftValues.filter((value) => !rightValues.includes(value)),
  }
}

const diffProfiles = (left, right) => {
  const paths = [
    'metadata.status',
    'metadata.risk',
    'metadata.launcher',
    'metadata.appBundle',
    'network.allowedDomains',
    'network.allowedRawTcp',
    'network.httpRules',
    'network.backend',
    'network.deniedDomains',
    'network.deniedDomainPresets',
    'network.allowLocalBinding',
    'network.allowLoopbackConnections',
    'network.allowLoopbackHighPorts',
    'network.allowLoopbackListeningHighPorts',
    'network.allowLoopbackPorts',
    'network.allowMachLookup',
    'network.allowUnixSockets',
    'filesystem.denyRead',
    'filesystem.allowRead',
    'filesystem.allowWrite',
    'filesystem.denyWrite',
  ]
  const changes = []
  for (const dottedPath of paths) {
    const leftValue = getAtPath(left.config, dottedPath)
    const rightValue = getAtPath(right.config, dottedPath)
    if (Array.isArray(leftValue) || Array.isArray(rightValue)) {
      const change = diffArray(leftValue, rightValue)
      if (change.added.length > 0 || change.removed.length > 0) {
        changes.push({ path: dottedPath, type: 'array', ...change })
      }
    } else if (leftValue !== rightValue) {
      changes.push({
        path: dottedPath,
        type: 'value',
        before: leftValue ?? null,
        after: rightValue ?? null,
      })
    }
  }
  return {
    left: { ref: left.ref, path: left.path },
    right: { ref: right.ref, path: right.path },
    changeCount: changes.length,
    changes,
  }
}

const formatProfileDiffText = (diff) => {
  const lines = [
    'Guard Profile Diff',
    `left: ${diff.left.ref} (${diff.left.path})`,
    `right: ${diff.right.ref} (${diff.right.path})`,
    `changes: ${diff.changeCount}`,
  ]
  for (const change of diff.changes) {
    if (change.type === 'array') {
      lines.push(`- ${change.path}`)
      if (change.added.length > 0) lines.push(`  added: ${change.added.join(' ')}`)
      if (change.removed.length > 0) lines.push(`  removed: ${change.removed.join(' ')}`)
    } else {
      lines.push(`- ${change.path}: ${change.before ?? '-'} -> ${change.after ?? '-'}`)
    }
  }
  return `${lines.join('\n')}\n`
}

const runDiffProfile = ({ repoRoot, left, right, json }) => {
  const diff = diffProfiles(
    resolveProfileRef({ repoRoot, ref: left }),
    resolveProfileRef({ repoRoot, ref: right }),
  )
  if (json) {
    emit(process.stdout, JSON.stringify(diff, null, 2))
  } else {
    process.stdout.write(formatProfileDiffText(diff))
  }
  process.exit(0)
}

const readNetworkLog = (logPath) => {
  const rows = []
  if (!fs.existsSync(logPath)) return rows
  for (const line of fs.readFileSync(logPath, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) continue
    try {
      rows.push(JSON.parse(line))
    } catch {}
  }
  return rows
}

const summarizeNetworkLog = (logPath) => {
  const events = readNetworkLog(logPath)
  const byHost = new Map()
  for (const event of events) {
    const key = `${event.host || '-'}:${event.port || '-'}`
    const current = byHost.get(key) || {
      host: event.host || '-',
      port: event.port || null,
      allowed: 0,
      denied: 0,
      reasons: new Set(),
    }
    if (event.allowed) current.allowed += 1
    else current.denied += 1
    if (event.reason) current.reasons.add(event.reason)
    byHost.set(key, current)
  }
  return {
    path: logPath,
    eventCount: events.length,
    hosts: [...byHost.values()].map((entry) => ({
      ...entry,
      reasons: [...entry.reasons].sort(),
    })),
  }
}

const formatNetworkLogText = (summary) => {
  const lines = [
    'Guard Network Log',
    `path: ${summary.path}`,
    `events: ${summary.eventCount}`,
  ]
  for (const host of summary.hosts) {
    lines.push(
      `- ${host.host}:${host.port || '-'} allowed=${host.allowed} denied=${host.denied} reasons=${host.reasons.join(',') || '-'}`,
    )
  }
  return `${lines.join('\n')}\n`
}

const runNetworkLog = ({ logPath, json }) => {
  const summary = summarizeNetworkLog(path.resolve(logPath))
  if (json) {
    emit(process.stdout, JSON.stringify(summary, null, 2))
  } else {
    process.stdout.write(formatNetworkLogText(summary))
  }
  process.exit(0)
}

const summarizeMonitorLog = ({ logPath, limit }) => {
  const resolved = path.resolve(logPath || resolveGuardEventLogPath())
  const events = readNetworkLog(resolved)
  const recent = events.slice(-limit).reverse()
  const counts = new Map()
  const byProfile = new Map()
  for (const event of events) {
    const type = event.type || 'unknown'
    counts.set(type, (counts.get(type) || 0) + 1)
    const profile = event.profile || '-'
    const current = byProfile.get(profile) || {
      profile,
      events: 0,
      allowed: 0,
      denied: 0,
    }
    current.events += 1
    if (type === 'network.decision') {
      if (event.allowed) current.allowed += 1
      else current.denied += 1
    }
    byProfile.set(profile, current)
  }
  return {
    path: resolved,
    eventCount: events.length,
    counts: [...counts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([type, count]) => ({ type, count })),
    profiles: [...byProfile.values()].sort((left, right) =>
      left.profile.localeCompare(right.profile),
    ),
    recent,
  }
}

const formatMonitorLogText = (summary) => {
  const lines = [
    'Guard Monitor Log',
    `path: ${summary.path}`,
    `events: ${summary.eventCount}`,
    '',
    'Profiles',
  ]
  if (summary.profiles.length === 0) {
    lines.push('- none')
  } else {
    for (const profile of summary.profiles) {
      lines.push(
        `- ${profile.profile}: events=${profile.events} allowed=${profile.allowed} denied=${profile.denied}`,
      )
    }
  }
  lines.push('', 'Recent Events')
  if (summary.recent.length === 0) {
    lines.push('- none')
  } else {
    for (const event of summary.recent) {
      const target = event.host
        ? `${event.host}${event.port ? `:${event.port}` : ''}`
        : event.command || '-'
      const result =
        event.type === 'network.decision'
          ? event.allowed
            ? 'allow'
            : 'deny'
          : event.code !== undefined
            ? `exit=${event.code ?? '-'}`
            : ''
      lines.push(
        `- ${event.at || '-'} ${event.profile || '-'} ${event.type || 'unknown'} ${target} ${result}`.trim(),
      )
    }
  }
  return `${lines.join('\n')}\n`
}

const runMonitorLog = ({ logPath, json, limit }) => {
  const summary = summarizeMonitorLog({ logPath, limit })
  if (json) {
    emit(process.stdout, JSON.stringify(summary, null, 2))
  } else {
    process.stdout.write(formatMonitorLogText(summary))
  }
  process.exit(0)
}

const runGuard = async ({ argv, repoRoot, invokedPath }) => {
  const parsed = parseGuardArgs(argv)
  if (parsed.mode === 'help') {
    emit(process.stdout, usage.trimEnd())
    process.exit(0)
  }
  if (parsed.mode === 'usage-error') {
    emit(process.stderr, usage.trimEnd())
    process.exit(2)
  }

  const cwd = process.cwd()
  if (parsed.mode === 'app') {
    await runGuardApp({
      argv: parsed.args,
      repoRoot,
      invokedPath,
      app: APP_LAUNCHERS[`guard-${parsed.appName}`],
    })
    return
  }
  if (parsed.mode === 'doctor') {
    runDoctor({
      repoRoot,
      invokedPath,
      profile: parsed.profile,
      cwd,
      json: parsed.json,
      tool: parsed.tool,
    })
  }
  if (parsed.mode === 'audit') {
    runAudit({
      repoRoot,
      profile: parsed.profile,
      cwd,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'settings') {
    runSettings({
      repoRoot,
      profile: parsed.profile,
      cwd,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'tls-status') {
    runTlsStatus({
      repoRoot,
      profile: parsed.profile,
      cwd,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'app-summary') {
    runAppSummary({
      repoRoot,
      profile: parsed.profile,
      cwd,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'daemon') {
    await runDaemon({
      repoRoot,
      args: parsed.args,
    })
  }
  if (parsed.mode === 'profile-doctor') {
    runProfileDoctor({
      repoRoot,
      profile: parsed.profile,
      cwd,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'profile-mutate-array') {
    runProfileMutateArray({
      cwd,
      profile: parsed.profile,
      field: parsed.field,
      value: parsed.value,
      action: parsed.action,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'profile-mutate-http-rule') {
    runProfileMutateHttpRule({
      cwd,
      profile: parsed.profile,
      rule: parsed.rule,
      action: parsed.action,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'profile-mutate-raw-tcp') {
    runProfileMutateRawTcpRule({
      cwd,
      profile: parsed.profile,
      rule: parsed.rule,
      action: parsed.action,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'profile-tls') {
    runProfileTls({
      cwd,
      profile: parsed.profile,
      action: parsed.action,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'list-profiles') {
    runListProfiles({
      repoRoot,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'list-templates') {
    runListTemplates({
      repoRoot,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'list-domain-presets') {
    runListDomainPresets({
      json: parsed.json,
    })
  }
  if (parsed.mode === 'diff-profile') {
    runDiffProfile({
      repoRoot,
      left: parsed.left,
      right: parsed.right,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'network-log') {
    runNetworkLog({
      logPath: parsed.logPath,
      json: parsed.json,
    })
  }
  if (parsed.mode === 'monitor-log') {
    runMonitorLog({
      logPath: parsed.logPath,
      json: parsed.json,
      limit: parsed.limit,
    })
  }
  if (parsed.mode === 'install-app') {
    runInstallApp({
      repoRoot,
      appName: parsed.appName,
      targetDir: parsed.targetDir,
      force: parsed.force,
    })
  }
  if (parsed.mode === 'install-monitor') {
    runInstallMonitor({
      repoRoot,
      targetDir: parsed.targetDir,
      force: parsed.force,
    })
  }
  if (parsed.mode === 'ui') {
    runUi({
      repoRoot,
      targetDir: parsed.targetDir,
    })
  }
  if (parsed.mode === 'install-apps') {
    runInstallApps({
      repoRoot,
      targetDir: parsed.targetDir,
      force: parsed.force,
    })
  }
  if (parsed.mode === 'setup') {
    await runSetup({
      repoRoot,
      includeShims: parsed.includeShims,
      force: parsed.force,
      binDir: parsed.binDir,
      codeRoot: parsed.codeRoot,
      yes: parsed.yes,
    })
  }
  if (parsed.mode === 'install') {
    runInstall({
      repoRoot,
      includeShims: parsed.includeShims,
      force: parsed.force,
      binDir: parsed.binDir,
      codeRoot: parsed.codeRoot,
    })
  }
  if (parsed.mode === 'init') {
    runInit({
      repoRoot,
      cwd,
      template: parsed.template,
      force: parsed.force,
    })
  }

  const { profile, askNetwork, deepEgress, args, showPolicyOnly } = parsed
  const resolved =
    findNearestProfile(cwd, profile) || findBuiltInProfile(repoRoot, profile, cwd)

  if (!resolved) {
    emit(
      process.stderr,
      `guard: no .guard/${profile}.json found above ${cwd} and no built-in profiles/${profile}.json`,
    )
    process.exit(1)
  }

  const realHome = process.env.HOME || ''
  const shimDirs = getShimDirs({ invokedPath, realHome })
  const sanitizedPath = sanitizePath(process.env.PATH || '', shimDirs)
  const runtimeNode = resolveToolCommand('node', sanitizedPath)
  if (runtimeNode.status !== 'resolved') {
    throw new Error(runtimeNode.reason)
  }

  const hash = crypto
    .createHash('sha256')
    .update(`${resolved.config}:${cwd}`)
    .digest('hex')
    .slice(0, 16)

  const guardHomeBase = process.env.GUARD_HOME_BASE || '/private/tmp/guard'
  const guardRun = path.join(guardHomeBase, `run-${hash}`)
  const guardHome = path.join(guardRun, 'home')
  const guardTmp = path.join(guardRun, 'tmp')
  const guardDockerConfig = path.join(guardRun, 'docker-config')
  fs.mkdirSync(guardHome, { recursive: true })
  fs.mkdirSync(guardTmp, { recursive: true })
  fs.mkdirSync(guardDockerConfig, { recursive: true })

  const runtimeConfigPath = path.join(guardTmp, 'config.json')
  const realTmpdir = (process.env.TMPDIR || '/tmp').replace(/\/+$/, '') || '/tmp'
  const replacements = {
    '${GUARD_RUN_DIR}': guardRun,
    '${GUARD_HOME_DIR}': guardHome,
    '${GUARD_TMP_DIR}': guardTmp,
    '${GUARD_PROJECT_DIR}': resolved.projectDir,
    '${GUARD_CWD}': cwd,
    '${GUARD_REAL_HOME}': realHome,
    '${GUARD_REAL_TMPDIR}': realTmpdir,
  }

  let cfg = expandConfig(
    loadProfileConfig({ repoRoot, configPath: resolved.config }),
    replacements,
    realHome,
  )
  if (askNetwork || parsed.discover) {
    cfg.network = {
      ...(cfg.network || {}),
      ask: true,
    }
  }
  if (deepEgress) {
    cfg.network = {
      ...(cfg.network || {}),
      backend: 'iron-proxy',
    }
  }
  if (parsed.discover) {
    cfg.network.discovery = true
  }
  cfg = addLoopbackListeningHighPorts(cfg)
  if (isFastVersionProbe(args)) {
    cfg = reduceNetworkForVersionProbe(cfg)
  }
  fs.writeFileSync(runtimeConfigPath, `${JSON.stringify(cfg, null, 2)}\n`)

  const discoveryReportPath = parsed.discover
    ? path.resolve(parsed.reportPath || path.join(guardRun, 'discovery-report.md'))
    : ''
  const discoveryNetworkLogPath = parsed.discover
    ? path.join(guardRun, 'network-log.jsonl')
    : ''
  if (discoveryReportPath) ensureParentDir(discoveryReportPath)
  if (discoveryNetworkLogPath) ensureParentDir(discoveryNetworkLogPath)

  const bannerMode = getBannerMode()
  if (bannerMode !== 'off') {
    const bannerOptions = {
      profile,
      cfg,
      guardRunDir: guardRun,
      replacements,
      realHome,
      cwd,
      colorMode: process.env.GUARD_COLOR || 'auto',
      tty: process.stderr.isTTY,
    }
    process.stderr.write(
      bannerMode === 'compact'
        ? formatCompactPolicyBanner(bannerOptions)
        : formatPolicyBanner(bannerOptions),
    )
  }

  if (showPolicyOnly) {
    process.exit(0)
  }

  const childEnv = {
    ...process.env,
    GUARD_SHIM_BYPASS: '1',
    GUARD_HOME_DIR: guardHome,
    GUARD_TMP_DIR: guardTmp,
    GUARD_INNER_PATH: sanitizedPath,
    GUARD_DOCKER_CONFIG: guardDockerConfig,
    GUARD_REAL_HOME: realHome,
    GUARD_RUN_DIR: guardRun,
    GUARD_PROJECT_DIR: resolved.projectDir,
    GUARD_CWD: cwd,
    GUARD_PROFILE: profile,
    GUARD_CONFIG: resolved.config,
    GUARD_EVENT_LOG: resolveGuardEventLogPath(),
    GUARD_RUNTIME_CWD:
      typeof cfg.workingDirectory === 'string' ? cfg.workingDirectory : '',
  }
  if (discoveryReportPath) {
    childEnv.GUARD_DISCOVERY_REPORT = discoveryReportPath
    childEnv.GUARD_DISCOVERY_PROFILE = profile
    childEnv.GUARD_DISCOVERY_CONFIG = resolved.config
    childEnv.GUARD_NETWORK_LOG = discoveryNetworkLogPath
  }
  if (childEnv.GUARD_ASK_NETWORK_UI === 'native' && !childEnv.GUARD_ASK_NETWORK_HELPER) {
    childEnv.GUARD_ASK_NETWORK_HELPER = buildNativeLauncherBinary(repoRoot)
  }
  delete childEnv.GUARD_SHIM_TOOL

  await exitLikeChild(runtimeNode.command[0], [
    path.resolve(repoRoot, 'lib/guard-runner.mjs'),
    runtimeConfigPath,
    path.join(guardTmp, 'profile.sb'),
    ...args,
  ], {
    env: childEnv,
  })
}

const runGuardShim = async ({ argv, invokedAs, repoRoot, invokedPath }) => {
  const tool = process.env.GUARD_SHIM_TOOL || invokedAs
  const codeRoot = resolveManagedRoot()
  const guardBin = process.env.GUARD_BIN || path.resolve(repoRoot, 'bin/guard')

  if (tool === 'deno') {
    emit(
      process.stderr,
      `deno is not supported by guard's native macOS runtime yet.\n\nUse one of these instead:\n  command deno ...\n  GUARD_SHIM_BYPASS=1 deno ...\n  DENO_GUARD_BYPASS=1 deno ...`,
    )
    process.exit(1)
  }

  if (tool === 'npx' || tool === 'corepack') {
    emit(
      process.stderr,
      `${tool} is disabled by guard.\n\nUse one of these instead:\n  pnpm run <script>\n  pnpm exec <binary> [args]\n  pnpm add -D <package> && pnpm exec <binary> [args]\n\nTo bypass intentionally:\n  GUARD_SHIM_BYPASS=1 ${tool} ...`,
    )
    process.exit(1)
  }

  const realHome = process.env.HOME || ''
  const shimDirs = getShimDirs({ invokedPath, realHome })
  const sanitizedPath = sanitizePath(process.env.PATH || '', shimDirs)
  const resolution = resolveToolCommand(tool, sanitizedPath)
  if (resolution.status !== 'resolved') {
    emit(process.stderr, `guard-shim: ${resolution.reason}`)
    process.exit(127)
  }

  const spec = TOOL_SPECS[tool]
  const bypassVar =
    process.env[spec.bypassEnv] ||
    (tool === 'python3' ? process.env.PYTHON_GUARD_BYPASS || '' : '') ||
    (tool === 'pip3' ? process.env.PIP_GUARD_BYPASS || '' : '')

  const execRealTool = async () => {
    const env = {
      ...process.env,
      PATH: sanitizedPath,
    }
    if (tool === 'pnpm' || tool === 'npm') {
      env.NODE_GUARD_BYPASS = '1'
    }
    await exitLikeChild(resolution.command[0], [...resolution.command.slice(1), ...argv], {
      env,
    })
  }

  if (
    process.env.GUARD_ACTIVE === '1' ||
    bypassVar === '1' ||
    process.env.GUARD_SHIM_BYPASS === '1'
  ) {
    await execRealTool()
    return
  }

  const cwd = process.cwd()
  const hasConfig = isInsideRoot(cwd, codeRoot) && !!findNearestProfile(cwd, 'guard')
  if (!hasConfig) {
    if (!isInsideRoot(cwd, codeRoot)) {
      await execRealTool()
      return
    }
    const confirmed = await confirmUnsandboxed(tool, cwd)
    if (confirmed) {
      await execRealTool()
      return
    }
    process.exit(130)
  }

  await exitLikeChild(guardBin, [resolution.path, ...argv], {
    env: process.env,
  })
}

const APP_LAUNCHERS = {
  'guard-zoom': {
    profile: 'zoom',
    env: 'GUARD_ZOOM_BIN',
    label: 'Zoom',
    bundle: '/Applications/zoom.us.app',
    icon: '/Applications/zoom.us.app/Contents/Resources/ZPLogo.icns',
    bundleIdentifier: 'dev.guard.zoom',
    command: '/Applications/zoom.us.app/Contents/MacOS/zoom.us',
  },
  'guard-teams': {
    profile: 'teams',
    env: 'GUARD_TEAMS_BIN',
    label: 'Teams',
    bundle: '/Applications/Microsoft Teams.app',
    icon: '/Applications/Microsoft Teams.app/Contents/Resources/AppIcon.icns',
    bundleIdentifier: 'dev.guard.teams',
    command: '/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams',
  },
  'guard-webex': {
    profile: 'webex',
    env: 'GUARD_WEBEX_BIN',
    label: 'Webex',
    bundle: '/Applications/Webex.app',
    icon: '/Applications/Webex.app/Contents/Resources/app_publishing_logo.icns',
    bundleIdentifier: 'dev.guard.webex',
    command: '/Applications/Webex.app/Contents/MacOS/Webex',
  },
}

const runGuardApp = async ({ argv, repoRoot, invokedPath, app }) => {
  const appBin = process.env[app.env] || app.command
  ensureExecutable(appBin, `guard-${app.profile}: ${app.label} binary`)
  await runGuard({
    argv: ['--profile', app.profile, '--', appBin, ...argv],
    repoRoot,
    invokedPath,
  })
}

export const main = async ({ argv, invokedPath, repoRoot }) => {
  const invokedAs = path.basename(invokedPath || 'guard')

  if (SHIM_TOOL_NAMES.has(invokedAs)) {
    await runGuardShim({ argv, invokedAs, repoRoot, invokedPath })
    return
  }
  if (APP_LAUNCHERS[invokedAs]) {
    await runGuardApp({ argv, repoRoot, invokedPath, app: APP_LAUNCHERS[invokedAs] })
    return
  }
  await runGuard({ argv, repoRoot, invokedPath })
}
