import path from 'node:path'
import fs from 'node:fs'

const NODE_PACKAGE_MANAGERS = new Set(['npm', 'pnpm', 'yarn', 'bun', 'npx', 'pnpx'])
const PYTHON_PACKAGE_MANAGERS = new Set(['pip', 'pip3', 'uv', 'poetry'])
const PACKAGE_MANAGERS = new Set([...NODE_PACKAGE_MANAGERS, ...PYTHON_PACKAGE_MANAGERS])
const NODE_LIFECYCLE_SCRIPTS = new Set(['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'])

const FLAG_VALUE_OPTIONS = new Set([
  '-C',
  '--cwd',
  '--dir',
  '--prefix',
  '--project',
  '--python',
  '--config',
  '--registry',
  '--globalconfig',
  '--userconfig',
])

const INSTALL_COMMANDS = {
  npm: new Set(['add', 'ci', 'i', 'install', 'link', 'rebuild', 'update', 'upgrade']),
  pnpm: new Set(['add', 'deploy', 'dlx', 'exec', 'fetch', 'i', 'import', 'install', 'rebuild', 'up', 'update']),
  yarn: new Set(['add', 'dlx', 'i', 'install', 'rebuild', 'up', 'upgrade']),
  bun: new Set(['add', 'i', 'install', 'pm', 'update', 'upgrade', 'x']),
  npx: new Set(['*']),
  pnpx: new Set(['*']),
  pip: new Set(['download', 'install', 'wheel']),
  pip3: new Set(['download', 'install', 'wheel']),
  poetry: new Set(['add', 'install', 'lock', 'sync', 'update']),
}

const UV_INSTALL_COMMANDS = new Set(['add', 'lock', 'run', 'sync', 'tool'])
const UV_PIP_INSTALL_COMMANDS = new Set(['compile', 'download', 'install', 'sync', 'wheel'])

const NODE_WRITE_PATTERNS = [
  'node_modules',
  'node_modules/**',
  'package.json',
  'package.json.*',
  'package-lock.json',
  'package-lock.json.*',
  'npm-shrinkwrap.json',
  'npm-shrinkwrap.json.*',
  'pnpm-lock.yaml',
  'pnpm-lock.yaml.*',
  'yarn.lock',
  'yarn.lock.*',
  'bun.lock',
  'bun.lockb',
  'bun.lockb.*',
  '.pnpm-store',
  '.pnpm-store/**',
  '_tmp_*',
]

const PYTHON_WRITE_PATTERNS = [
  '.venv',
  '.venv/**',
  'venv',
  'venv/**',
  'pyproject.toml',
  'pyproject.toml.*',
  'uv.lock',
  'uv.lock.*',
  'poetry.lock',
  'poetry.lock.*',
  'requirements.txt',
  'requirements-*.txt',
]

const DANGEROUS_FILES = [
  '.env',
  '.env.*',
  '.aws',
  '.azure',
  '.gcloud',
  '.config/gcloud',
  '.kube',
  '.ssh',
  '.gnupg',
  '.docker/config.json',
  '.netrc',
  '.git-credentials',
  '.pgpass',
  '.config/gh',
  '.npmrc',
  '.pypirc',
  '.cargo/credentials',
  '.cargo/credentials.toml',
  '.gem/credentials',
]

const GIT_HOOK_PATTERNS = ['.git/hooks', '.git/hooks/**']

const unique = (values = []) => {
  const out = []
  for (const value of values) {
    if (value === '' || value === null || value === undefined) continue
    const stringValue = String(value)
    if (!out.includes(stringValue)) out.push(stringValue)
  }
  return out
}

const asArray = (value) => (Array.isArray(value) ? value : [])

const cleanPath = (value) => path.normalize(String(value || '').replace(/\/+$/, '') || '/')

const joinIfRoot = (root, child) =>
  typeof root === 'string' && root
    ? path.join(root, child)
    : ''

const safeReadJson = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

const relativePath = (root, file) => {
  const rel = path.relative(root, file)
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : file
}

const readTextIfExists = (file) => {
  try {
    return fs.readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

const yamlBooleanValue = (content, key) => {
  const pattern = new RegExp(`^\\s*${key}\\s*:\\s*(true|false)\\s*(?:#.*)?$`, 'im')
  const match = pattern.exec(content)
  return match ? match[1].toLowerCase() === 'true' : null
}

const npmrcBooleanValue = (content, key) => {
  const pattern = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*(true|false)\\s*(?:#.*)?$`, 'im')
  const match = pattern.exec(content)
  return match ? match[1].toLowerCase() === 'true' : null
}

const packageLocator = (pkg, manifestPath, root) => {
  const name = String(pkg?.name || path.basename(path.dirname(manifestPath)) || '').trim()
  const version = String(pkg?.version || '').trim()
  return {
    name,
    version,
    package: version ? `${name}@${version}` : name,
    path: relativePath(root, manifestPath),
  }
}

const lifecycleScriptsFromManifest = (pkg) => {
  const scripts = pkg?.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts)
    ? pkg.scripts
    : {}
  return Object.entries(scripts)
    .filter(([name, value]) => NODE_LIFECYCLE_SCRIPTS.has(name) && typeof value === 'string' && value.trim())
    .map(([name, command]) => ({ name, command }))
}

const collectManifestPaths = ({ root, includeNodeModules = false, maxManifests = 2000 }) => {
  const manifests = []
  const seen = new Set()
  const addManifest = (file) => {
    const normalized = path.resolve(file)
    if (seen.has(normalized) || manifests.length >= maxManifests) return
    seen.add(normalized)
    manifests.push(normalized)
  }

  const rootManifest = path.join(root, 'package.json')
  if (fs.existsSync(rootManifest)) addManifest(rootManifest)

  if (!includeNodeModules) return manifests

  const walk = (dir, depth = 0) => {
    if (manifests.length >= maxManifests || depth > 8) return
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (manifests.length >= maxManifests) return
      const child = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' && path.basename(dir) !== '.pnpm') {
          walk(child, depth + 1)
          continue
        }
        if (entry.name === '.pnpm' || entry.name.startsWith('@') || depth < 4) {
          walk(child, depth + 1)
        }
      } else if (entry.isFile() && entry.name === 'package.json') {
        addManifest(child)
      }
    }
  }

  walk(path.join(root, 'node_modules'), 0)
  return manifests
}

export const scanNodeLifecycleScripts = ({
  projectDir,
  includeNodeModules = true,
  maxManifests = 2000,
} = {}) => {
  const root = path.resolve(projectDir || process.cwd())
  const findings = []
  const manifests = collectManifestPaths({ root, includeNodeModules, maxManifests })
  for (const manifest of manifests) {
    const pkg = safeReadJson(manifest)
    if (!pkg || typeof pkg !== 'object') continue
    const scripts = lifecycleScriptsFromManifest(pkg)
    if (scripts.length === 0) continue
    findings.push({
      ...packageLocator(pkg, manifest, root),
      lifecycleScripts: scripts,
      source: manifest === path.join(root, 'package.json') ? 'project' : 'dependency',
    })
  }
  return {
    type: 'node-lifecycle-script-scan',
    root,
    includeNodeModules,
    scannedManifests: manifests.length,
    truncated: manifests.length >= maxManifests,
    findings,
    summary: {
      packagesWithLifecycleScripts: findings.length,
      lifecycleScriptCount: findings.reduce((sum, item) => sum + item.lifecycleScripts.length, 0),
    },
  }
}

export const analyzePnpmBuildPolicy = ({ projectDir } = {}) => {
  const root = path.resolve(projectDir || process.cwd())
  const workspacePath = path.join(root, 'pnpm-workspace.yaml')
  const npmrcPath = path.join(root, '.npmrc')
  const workspace = readTextIfExists(workspacePath)
  const npmrc = readTextIfExists(npmrcPath)
  const dangerouslyAllowAllBuilds = yamlBooleanValue(workspace, 'dangerouslyAllowAllBuilds')
  const strictDepBuilds = yamlBooleanValue(workspace, 'strictDepBuilds')
  const minimumReleaseAgeStrict = yamlBooleanValue(workspace, 'minimumReleaseAgeStrict')
  const npmrcIgnoreScripts = npmrcBooleanValue(npmrc, 'ignore-scripts')
  const issues = []

  if (dangerouslyAllowAllBuilds === true) {
    issues.push({
      severity: 'error',
      code: 'pnpm-dangerously-allow-all-builds',
      file: workspacePath,
      message: 'pnpm-workspace.yaml enables dangerouslyAllowAllBuilds, which lets all dependency lifecycle scripts run without review.',
    })
  }
  if (strictDepBuilds === false) {
    issues.push({
      severity: 'warning',
      code: 'pnpm-strict-dep-builds-disabled',
      file: workspacePath,
      message: 'pnpm strictDepBuilds is disabled; unreviewed dependency build scripts may be downgraded from errors to warnings.',
    })
  }
  if (npmrcIgnoreScripts === false) {
    issues.push({
      severity: 'warning',
      code: 'npmrc-ignore-scripts-disabled',
      file: npmrcPath,
      message: '.npmrc disables ignore-scripts. Guard install hardening overrides this for guarded installs.',
    })
  }

  return {
    workspacePath: fs.existsSync(workspacePath) ? workspacePath : null,
    npmrcPath: fs.existsSync(npmrcPath) ? npmrcPath : null,
    dangerouslyAllowAllBuilds,
    strictDepBuilds,
    minimumReleaseAgeStrict,
    npmrcIgnoreScripts,
    issues,
  }
}

const managerNameFromCommand = (command = '') => {
  const base = path.basename(String(command || ''))
  if (base === 'pnpm.cjs') return 'pnpm'
  if (base === 'npm-cli.js') return 'npm'
  if (PACKAGE_MANAGERS.has(base)) return base
  return ''
}

const firstNonFlagArg = (args = [], start = 1) => {
  for (let index = start; index < args.length; index += 1) {
    const arg = String(args[index] || '')
    if (!arg) continue
    if (arg === '--') return String(args[index + 1] || '')
    if (FLAG_VALUE_OPTIONS.has(arg)) {
      index += 1
      continue
    }
    if (arg.startsWith('--') && !arg.includes('=')) {
      continue
    }
    if (arg.startsWith('-')) {
      continue
    }
    return arg
  }
  return ''
}

export const detectInstallSandboxPackageManager = (commandArgs = []) =>
  managerNameFromCommand(commandArgs[0])

export const isInstallSandboxCommand = (commandArgs = []) => {
  const packageManager = detectInstallSandboxPackageManager(commandArgs)
  if (!packageManager) return false
  if (packageManager === 'npx' || packageManager === 'pnpx') return true

  const command = firstNonFlagArg(commandArgs, 1)
  if (!command) return false

  if (packageManager === 'uv') {
    if (UV_INSTALL_COMMANDS.has(command)) return true
    if (command === 'pip') {
      return UV_PIP_INSTALL_COMMANDS.has(firstNonFlagArg(commandArgs, commandArgs.indexOf(command) + 1))
    }
    return false
  }

  const commands = INSTALL_COMMANDS[packageManager]
  return commands?.has(command) || commands?.has('*') || false
}

const normalizeInstallSandboxConfig = (value) => {
  if (value === true) return { enabled: true, configured: true }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return { ...value, enabled: value.enabled !== false, configured: true }
  }
  return { enabled: false, configured: false }
}

const presetForPackageManager = (packageManager, { projectDir, guardRunDir }) => {
  const projectPatterns = NODE_PACKAGE_MANAGERS.has(packageManager)
    ? NODE_WRITE_PATTERNS
    : PYTHON_PACKAGE_MANAGERS.has(packageManager)
      ? PYTHON_WRITE_PATTERNS
      : [...NODE_WRITE_PATTERNS, ...PYTHON_WRITE_PATTERNS]

  return {
    name: NODE_PACKAGE_MANAGERS.has(packageManager)
      ? 'node-install-restrictive'
      : PYTHON_PACKAGE_MANAGERS.has(packageManager)
        ? 'python-install-restrictive'
        : 'generic-install-restrictive',
    allowWrite: unique([
      guardRunDir,
      ...projectPatterns.map((entry) => joinIfRoot(projectDir, entry)),
    ]),
  }
}

const isBroadProjectWrite = (value, projectDir) => {
  if (!projectDir || typeof value !== 'string') return false
  const project = cleanPath(projectDir)
  const candidate = cleanPath(value)
  return candidate === project ||
    candidate === `${project}/**` ||
    candidate === `${project}/*`
}

const dangerousSuppressionNames = ({ allowEntries, projectDir, realHome }) => {
  const allowed = new Set(asArray(allowEntries).map(cleanPath))
  const suppressed = new Set()
  for (const name of DANGEROUS_FILES) {
    const projectPath = joinIfRoot(projectDir, name)
    const homePath = joinIfRoot(realHome, name)
    if ((projectPath && allowed.has(cleanPath(projectPath))) || (homePath && allowed.has(cleanPath(homePath)))) {
      suppressed.add(name)
    }
  }
  return suppressed
}

const mandatoryDenyPatterns = ({ projectDir, realHome, allowGitConfig, allowRead, allowWrite }) => {
  const suppressedRead = dangerousSuppressionNames({ allowEntries: allowRead, projectDir, realHome })
  const suppressedWrite = dangerousSuppressionNames({ allowEntries: allowWrite, projectDir, realHome })
  const denyRead = []
  const denyWrite = []

  for (const name of DANGEROUS_FILES) {
    const entries = [
      joinIfRoot(projectDir, name),
      joinIfRoot(projectDir, path.join('**', name)),
      joinIfRoot(realHome, name),
    ]
    if (!suppressedRead.has(name)) denyRead.push(...entries)
    if (!suppressedWrite.has(name)) denyWrite.push(...entries)
  }

  const gitHookEntries = [
    ...GIT_HOOK_PATTERNS.map((entry) => joinIfRoot(projectDir, entry)),
    ...GIT_HOOK_PATTERNS.map((entry) => joinIfRoot(realHome, entry)),
  ]
  denyRead.push(...gitHookEntries)
  denyWrite.push(...gitHookEntries)

  if (allowGitConfig !== true) {
    denyWrite.push(joinIfRoot(projectDir, '.git/config'))
    denyWrite.push(joinIfRoot(realHome, '.git/config'))
  }

  return {
    denyRead: unique(denyRead),
    denyWrite: unique(denyWrite),
  }
}

const parseNetOverride = (value) => {
  const raw = String(value || '').trim()
  if (!raw) return {}
  const host = raw.includes(':') ? raw.slice(0, raw.lastIndexOf(':')) : raw
  if (['localhost', '127.0.0.1', '::1'].includes(host)) {
    const port = Number(raw.slice(raw.lastIndexOf(':') + 1))
    return Number.isInteger(port) && port > 0 && port <= 65535
      ? { allowLoopbackPort: [port] }
      : {}
  }
  return { allowedDomains: [host.toLowerCase()] }
}

export const parseInstallSandboxAllow = (raw = '') => {
  const value = String(raw || '')
  const separator = value.indexOf('=')
  if (separator < 1 || separator === value.length - 1) {
    throw new Error(`invalid --install-sandbox-allow ${JSON.stringify(raw)}; expected type=value`)
  }
  const type = value.slice(0, separator)
  const target = value.slice(separator + 1)
  if (type === 'read') return { allowRead: [target] }
  if (type === 'write') return { allowWrite: [target] }
  if (type === 'exec') return { allowExec: [target] }
  if (type === 'domain') return { allowedDomains: [target.toLowerCase()] }
  if (type === 'net' || type === 'net-connect') return parseNetOverride(target)
  if (type === 'net-bind') {
    const port = Number(target.slice(target.lastIndexOf(':') + 1))
    return Number.isInteger(port) && port > 0 && port <= 65535
      ? { allowLoopbackPort: [port] }
      : {}
  }
  throw new Error(`invalid --install-sandbox-allow type ${JSON.stringify(type)}; use read, write, exec, domain, net, or net-bind`)
}

const mergeAllowOverrides = (items = []) => {
  const merged = {
    allowRead: [],
    allowWrite: [],
    allowExec: [],
    allowedDomains: [],
    allowLoopbackPort: [],
  }
  for (const item of items) {
    merged.allowRead.push(...asArray(item.allowRead))
    merged.allowWrite.push(...asArray(item.allowWrite))
    merged.allowExec.push(...asArray(item.allowExec))
    merged.allowedDomains.push(...asArray(item.allowedDomains))
    merged.allowLoopbackPort.push(...asArray(item.allowLoopbackPort))
  }
  return {
    allowRead: unique(merged.allowRead),
    allowWrite: unique(merged.allowWrite),
    allowExec: unique(merged.allowExec),
    allowedDomains: unique(merged.allowedDomains),
    allowLoopbackPort: unique(merged.allowLoopbackPort).map(Number).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535),
  }
}

export const applyInstallSandboxPolicy = (config = {}, options = {}) => {
  const cfg = structuredClone(config)
  const supplyChain = cfg.supplyChain && typeof cfg.supplyChain === 'object'
    ? cfg.supplyChain
    : {}
  const installSandbox = normalizeInstallSandboxConfig(supplyChain.installSandbox)
  const packageManager = detectInstallSandboxPackageManager(options.commandArgs || [])
  const commandMatches = isInstallSandboxCommand(options.commandArgs || [])
  const force = options.force === true
  const disabled = options.disabled === true || (!force && installSandbox.configured && installSandbox.enabled === false)
  const active = !disabled && (force || (installSandbox.enabled && (installSandbox.enforceAlways === true || commandMatches)))

  if (!active) {
    return {
      config: cfg,
      active: false,
      packageManager,
      commandMatches,
      reason: disabled ? 'disabled' : 'not-install-command',
    }
  }

  const projectDir = options.projectDir || options.cwd || ''
  const guardRunDir = options.guardRunDir || ''
  const realHome = options.realHome || ''
  const preset = presetForPackageManager(packageManager, { projectDir, guardRunDir })
  const profileAllow = mergeAllowOverrides([
    installSandbox,
    ...(Array.isArray(options.allowOverrides) ? options.allowOverrides : []),
  ])
  const mandatory = mandatoryDenyPatterns({
    projectDir,
    realHome,
    allowGitConfig: installSandbox.allowGitConfig === true,
    allowRead: profileAllow.allowRead,
    allowWrite: profileAllow.allowWrite,
  })
  const filesystem = cfg.filesystem && typeof cfg.filesystem === 'object'
    ? cfg.filesystem
    : {}
  const processPolicy = cfg.process && typeof cfg.process === 'object'
    ? cfg.process
    : {}
  const network = cfg.network && typeof cfg.network === 'object'
    ? cfg.network
    : {}
  const allowWriteBase = installSandbox.keepProfileWrites === true
    ? asArray(filesystem.allowWrite)
    : asArray(filesystem.allowWrite).filter((entry) => !isBroadProjectWrite(entry, projectDir))

  cfg.filesystem = {
    ...filesystem,
    allowRead: unique([
      ...asArray(filesystem.allowRead),
      ...profileAllow.allowRead,
    ]),
    allowWrite: unique([
      ...allowWriteBase,
      ...preset.allowWrite,
      ...profileAllow.allowWrite,
    ]),
    denyReadAfterAllow: unique([
      ...asArray(filesystem.denyReadAfterAllow),
      ...mandatory.denyRead,
      ...asArray(installSandbox.denyRead),
    ]),
    denyWrite: unique([
      ...asArray(filesystem.denyWrite),
      ...mandatory.denyWrite,
      ...asArray(installSandbox.denyWrite),
    ]),
  }

  cfg.process = {
    ...processPolicy,
    allowedExecutables: unique([
      ...asArray(processPolicy.allowedExecutables),
      ...profileAllow.allowExec,
    ]),
  }

  cfg.network = {
    ...network,
    allowedDomains: unique([
      ...asArray(network.allowedDomains),
      ...profileAllow.allowedDomains,
    ]),
    allowLoopbackPorts: unique([
      ...asArray(network.allowLoopbackPorts),
      ...profileAllow.allowLoopbackPort,
    ]).map(Number).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535),
  }

  const { configured: _configured, ...installSandboxConfig } = installSandbox
  cfg.supplyChain = {
    ...supplyChain,
    installHardening: installSandbox.installHardening === false ? supplyChain.installHardening === true : true,
    installSandbox: {
      ...installSandboxConfig,
      enabled: true,
    },
    installSandboxActive: {
      active: true,
      packageManager: packageManager || 'generic',
      commandMatches,
      forced: force,
      profile: preset.name,
      enforceAlways: installSandbox.enforceAlways === true,
      allowOverrides: profileAllow,
    },
  }

  return {
    config: cfg,
    active: true,
    packageManager: packageManager || 'generic',
    commandMatches,
    profile: preset.name,
  }
}
