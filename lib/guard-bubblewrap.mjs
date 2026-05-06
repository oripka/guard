import fs from 'node:fs'
import path from 'node:path'

const defaultRuntimeDirs = [
  '/bin',
  '/etc',
  '/lib',
  '/lib64',
  '/opt',
  '/run',
  '/sbin',
  '/usr',
]

const normalizePath = (value, cwd = process.cwd()) => {
  if (typeof value !== 'string' || !value.trim()) return ''
  const expanded = value.startsWith('~/')
    ? path.join(process.env.GUARD_REAL_HOME || process.env.HOME || '', value.slice(2))
    : value
  return path.resolve(cwd, expanded)
}

const uniqueExistingPaths = (values) => {
  const seen = new Set()
  const paths = []
  for (const value of values) {
    if (!value || seen.has(value)) continue
    seen.add(value)
    if (fs.existsSync(value)) paths.push(value)
  }
  return paths
}

const addBind = (args, mode, source, destination = source) => {
  args.push(mode, source, destination)
}

export const linuxSandboxBackend = ({ network = {}, networkUnrestricted = false, proxyEnabled = false } = {}) => {
  if (process.platform !== 'linux') return 'unsupported'
  if (networkUnrestricted === true) return 'bubblewrap-host-network'
  if (proxyEnabled) return 'unsupported-proxy-network'
  if (Array.isArray(network.allowedRawTcp) && network.allowedRawTcp.length > 0) {
    return 'unsupported-raw-tcp'
  }
  if (
    network.allowLocalBinding ||
    network.allowLoopbackConnections ||
    (Array.isArray(network.allowLoopbackPorts) && network.allowLoopbackPorts.length > 0)
  ) {
    return 'bubblewrap-loopback-network'
  }
  return 'bubblewrap-deny-network'
}

export const assertLinuxBubblewrapSupported = (cfg = {}, { proxyEnabled = false } = {}) => {
  const network = cfg.network || {}
  const backend = linuxSandboxBackend({
    network,
    networkUnrestricted: cfg.networkUnrestricted === true,
    proxyEnabled,
  })
  if (backend === 'unsupported') {
    throw new Error('guard: Linux sandboxing requires bubblewrap and is only available on Linux')
  }
  if (backend === 'unsupported-proxy-network') {
    throw new Error(
      'guard: Linux bubblewrap backend does not yet support Guard proxy/domain/httpRules enforcement; use networkUnrestricted for trusted commands or run on macOS for per-run proxy policy',
    )
  }
  if (backend === 'unsupported-raw-tcp') {
    throw new Error(
      'guard: Linux bubblewrap backend does not yet support network.allowedRawTcp; use proxy-aware tooling or a future Linux network-policy backend',
    )
  }
  return backend
}

export const buildBubblewrapArgs = ({
  cfg = {},
  commandArgs = [],
  env = [],
  cwd = process.cwd(),
  executablePaths = [],
  clearEnv = false,
} = {}) => {
  const filesystem = cfg.filesystem || {}
  const projectDir = normalizePath(process.env.GUARD_PROJECT_DIR || cwd, cwd)
  const runDir = normalizePath(process.env.GUARD_RUN_DIR || '', cwd)
  const homeDir = normalizePath(process.env.GUARD_HOME_DIR || '', cwd)
  const tmpDir = normalizePath(process.env.GUARD_TMP_DIR || '', cwd)
  const runtimeCwd = normalizePath(process.env.GUARD_RUNTIME_CWD || cwd, cwd)
  const allowRead = Array.isArray(filesystem.allowRead) ? filesystem.allowRead : [projectDir, runDir]
  const allowWrite = Array.isArray(filesystem.allowWrite) ? filesystem.allowWrite : []
  const backend = assertLinuxBubblewrapSupported(cfg, { proxyEnabled: false })

  const args = ['--die-with-parent', '--unshare-pid', '--proc', '/proc', '--dev', '/dev']
  if (clearEnv) args.push('--clearenv')
  if (backend === 'bubblewrap-deny-network' || backend === 'bubblewrap-loopback-network') {
    args.push('--unshare-net')
  }

  for (const dir of uniqueExistingPaths(defaultRuntimeDirs)) {
    addBind(args, '--ro-bind', dir)
  }

  for (const source of uniqueExistingPaths([
    projectDir,
    runDir,
    ...allowRead.map((entry) => normalizePath(entry, cwd)),
    ...executablePaths.map((entry) => normalizePath(entry, cwd)),
  ])) {
    addBind(args, '--ro-bind-try', source)
  }

  for (const source of uniqueExistingPaths([
    projectDir,
    runDir,
    ...allowWrite.map((entry) => normalizePath(entry, cwd)),
  ])) {
    addBind(args, '--bind-try', source)
  }

  if (homeDir) {
    fs.mkdirSync(homeDir, { recursive: true })
    addBind(args, '--bind', homeDir)
  }
  if (tmpDir) {
    fs.mkdirSync(tmpDir, { recursive: true })
    addBind(args, '--bind', tmpDir)
    args.push('--tmpfs', '/tmp')
  }

  if (runtimeCwd) args.push('--chdir', runtimeCwd)
  for (const entry of env) {
    const separator = entry.indexOf('=')
    if (separator <= 0) continue
    args.push('--setenv', entry.slice(0, separator), entry.slice(separator + 1))
  }

  if (backend === 'bubblewrap-loopback-network') {
    args.push(
      '/bin/sh',
      '-lc',
      'if command -v ip >/dev/null 2>&1; then ip link set lo up 2>/dev/null || true; elif test -x /sbin/ip; then /sbin/ip link set lo up 2>/dev/null || true; fi; exec "$@"',
      'guard-bwrap-loopback',
      '/usr/bin/env',
      ...commandArgs,
    )
  } else {
    args.push('/usr/bin/env', ...commandArgs)
  }
  return args
}
