import {
  containsGlobChars,
  emitNameRule,
  emitPathRule,
  escapeSeatbelt,
  generateMoveBlockingRules,
  globToRegex,
  normalizePathForSandbox,
} from './guard-utils.mjs'

const DEFAULT_LOG_TAG = 'guard'

const DEFAULT_MACH_LOOKUPS = [
  'com.apple.audio.systemsoundserver',
  'com.apple.distributed_notifications@Uv3',
  'com.apple.FontObjectsServer',
  'com.apple.fonts',
  'com.apple.logd',
  'com.apple.lsd.mapdb',
  'com.apple.PowerManagement.control',
  'com.apple.system.logger',
  'com.apple.system.notification_center',
  'com.apple.system.opendirectoryd.libinfo',
  'com.apple.system.opendirectoryd.membership',
  'com.apple.bsd.dirhelper',
  'com.apple.securityd.xpc',
  'com.apple.coreservices.launchservicesd',
  'com.apple.SecurityServer',
]

const DEFAULT_SYSCTL_READ = [
  'hw.activecpu',
  'hw.cpufrequency',
  'hw.ephemeral_storage',
  'hw.machine',
  'hw.memsize',
  'hw.ncpu',
  'hw.pagesize_compat',
  'kern.argmax',
  'kern.bootargs',
  'kern.hostname',
  'kern.iossupportversion',
  'kern.ngroups',
  'kern.osproductversion',
  'kern.osrelease',
  'kern.ostype',
  'kern.osvariant_status',
  'kern.osversion',
  'kern.version',
  'net.routetable.0.0.3.0',
  'security.mac.lockdown_mode_state',
  'machdep.cpu.brand_string',
  'hw.optional.arm*',
  'kern.proc.pid.*',
  'machdep.cpu.*',
]

const DEFAULT_IOKIT_REGISTRY_ENTRY_CLASSES = [
  'IOSurfaceRootUserClient',
  'RootDomainUserClient',
]

const DEFAULT_IOKIT_USER_CLIENT_CLASSES = ['IOSurfaceSendRight']

const DEFAULT_FILE_IOCTL_LITERALS = [
  '/dev/null',
  '/dev/zero',
  '/dev/random',
  '/dev/urandom',
  '/dev/dtracehelper',
  '/dev/tty',
]

const DEFAULT_DENY_READ = [
  '/Users',
  '/Volumes',
  '/Applications',
  '/cores',
  '/home',
]

const getDefaultAllowRead = (projectDir, cwd, guardRunDir) =>
  [projectDir || cwd, guardRunDir].filter(
    (value, index, values) =>
      typeof value === 'string' &&
      value.length > 0 &&
      values.indexOf(value) === index,
  )

const generateReadRules = (
  filesystem,
  writeAllowPaths,
  logTag,
  cwd,
  allowFileIssueExtension,
  guardRunDir,
  projectDir,
) => {
  const rules = ['(allow file-read*)']
  const denyRead = filesystem?.denyRead ?? DEFAULT_DENY_READ
  const allowRead =
    filesystem?.allowRead ?? getDefaultAllowRead(projectDir, cwd, guardRunDir)

  for (const pathPattern of denyRead) {
    rules.push(...emitPathRule('deny', 'file-read*', pathPattern, logTag, cwd))
  }

  for (const pathPattern of allowRead) {
    rules.push(...emitPathRule('allow', 'file-read*', pathPattern, logTag, cwd))
    if (allowFileIssueExtension) {
      rules.push(
        ...emitPathRule(
          'allow',
          'file-issue-extension',
          pathPattern,
          logTag,
          cwd,
        ),
      )
    }
  }

  if (denyRead.length > 0) {
    rules.push('(allow file-read-metadata', '  (vnode-type DIRECTORY))')
  }

  rules.push(...generateMoveBlockingRules(denyRead, logTag, cwd))

  for (const pathPattern of writeAllowPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern, cwd)
    if (containsGlobChars(normalizedPath)) {
      rules.push(
        '(allow file-write-unlink',
        `  (regex ${escapeSeatbelt(globToRegex(normalizedPath))})`,
        `  (with message ${escapeSeatbelt(logTag)}))`,
      )
    } else {
      rules.push(
        '(allow file-write-unlink',
        `  (subpath ${escapeSeatbelt(normalizedPath)})`,
        `  (with message ${escapeSeatbelt(logTag)}))`,
      )
    }
  }

  return rules
}

const generateWriteRules = (
  filesystem,
  logTag,
  cwd,
  allowFileIssueExtension,
) => {
  const rules = []
  const allowWrite = filesystem?.allowWrite || []
  const denyWrite = filesystem?.denyWrite || []

  for (const pathPattern of allowWrite) {
    rules.push(...emitPathRule('allow', 'file-write*', pathPattern, logTag, cwd))
    if (allowFileIssueExtension) {
      rules.push(
        ...emitPathRule(
          'allow',
          'file-issue-extension',
          pathPattern,
          logTag,
          cwd,
        ),
      )
    }
  }

  for (const pathPattern of denyWrite) {
    rules.push(...emitPathRule('deny', 'file-write*', pathPattern, logTag, cwd))
  }

  rules.push(...generateMoveBlockingRules(denyWrite, logTag, cwd))
  return rules
}

const generateMachLookupRules = (
  allowMachLookup = [],
  allowMachIssueExtension = false,
) => {
  const rules = []
  for (const name of allowMachLookup) {
    rules.push(emitNameRule('allow', 'mach-lookup', 'global-name', name))
    if (allowMachIssueExtension) {
      rules.push(
        emitNameRule('allow', 'mach-issue-extension', 'global-name', name),
      )
    }
  }
  return rules
}

const generateUnixSocketRules = (allowUnixSockets = [], cwd) => {
  if (allowUnixSockets.length === 0) return []
  const rules = ['(allow system-socket (socket-domain AF_UNIX))']
  for (const socketPath of allowUnixSockets) {
    const normalizedPath = normalizePathForSandbox(socketPath, cwd)
    rules.push(
      `(allow network-bind (local unix-socket (subpath ${escapeSeatbelt(normalizedPath)})))`,
    )
    rules.push(
      `(allow network-outbound (remote unix-socket (subpath ${escapeSeatbelt(normalizedPath)})))`,
    )
  }
  return rules
}

const normalizeLoopbackPort = (port) => {
  const value = Number(port)
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`guard: invalid network.allowLoopbackPorts entry: ${port}`)
  }
  return value
}

const generateLoopbackOutboundRules = (network = {}) => {
  if (network.allowLoopbackConnections) {
    return ['(allow network-outbound (remote ip "localhost:*"))']
  }

  const ports = new Set()
  if (Array.isArray(network.allowLoopbackPorts)) {
    for (const port of network.allowLoopbackPorts) {
      ports.add(normalizeLoopbackPort(port))
    }
  }
  if (network.allowLoopbackHighPorts) {
    for (let port = 49152; port <= 65535; port += 1) {
      ports.add(port)
    }
  }

  return [...ports]
    .sort((left, right) => left - right)
    .map((port) => `(allow network-outbound (remote ip "localhost:${port}"))`)
}

const generateSysctlReadRules = (extraSysctls = []) => {
  const rules = []
  for (const name of [...DEFAULT_SYSCTL_READ, ...extraSysctls]) {
    rules.push(emitNameRule('allow', 'sysctl-read', 'sysctl-name', name))
  }
  return rules
}

const generateIokitRules = (system = {}) => {
  const entryClasses = [
    ...DEFAULT_IOKIT_REGISTRY_ENTRY_CLASSES,
    ...(system.allowIokitRegistryEntryClass || []),
  ]
  const userClientClasses = [
    ...DEFAULT_IOKIT_USER_CLIENT_CLASSES,
    ...(system.allowIokitUserClientClass || []),
  ]

  return [
    '(allow iokit-open',
    ...entryClasses.map(
      (name) => `  (iokit-registry-entry-class ${escapeSeatbelt(name)})`,
    ),
    ...userClientClasses.map(
      (name) => `  (iokit-user-client-class ${escapeSeatbelt(name)})`,
    ),
    ')',
    '(allow iokit-get-properties)',
  ]
}

const generateFileIoctlRules = (system = {}) => {
  const literals = [
    ...DEFAULT_FILE_IOCTL_LITERALS,
    ...(system.allowFileIoctl || []),
  ]

  return [
    ...literals.map(
      (literal) =>
        `(allow file-ioctl (literal ${escapeSeatbelt(literal)}))`,
    ),
    '(allow file-ioctl file-read-data file-write-data',
    `  (require-all`,
    `    (literal ${escapeSeatbelt('/dev/null')})`,
    '    (vnode-type CHARACTER-DEVICE)',
    '  )',
    ')',
  ]
}

export const generateProfile = (config, options = {}) => {
  const logTag = options.logTag || DEFAULT_LOG_TAG
  const cwd = options.cwd || process.cwd()
  const filesystem = config.filesystem || {}
  const network = config.network || {}
  const system = config.system || {}
  const allowFileIssueExtension = system.allowFileIssueExtension === true
  const allowMachIssueExtension = system.allowMachIssueExtension === true
  const httpProxyPort = options.httpProxyPort
  const socksProxyPort = options.socksProxyPort
  const guardRunDir = options.guardRunDir
  const projectDir = options.projectDir

  if (
    Array.isArray(network.allowedDomains) &&
    network.allowedDomains.length > 0 &&
    !httpProxyPort &&
    !socksProxyPort &&
    !config.networkUnrestricted
  ) {
    throw new Error(
      'guard: allowedDomains is not supported by the native runtime yet; refusing to run fail-open',
    )
  }

  const profile = [
    '(version 1)',
    `(deny default (with message ${escapeSeatbelt(logTag)}))`,
    '',
    '; Process',
    '(allow process-exec)',
    '(allow process-fork)',
    '(allow process-info* (target same-sandbox))',
    '(allow signal (target same-sandbox))',
    '(allow mach-priv-task-port (target same-sandbox))',
    '',
    '; User preferences',
    '(allow user-preference-read)',
    '',
    '; Mach IPC',
    '(allow mach-lookup',
    ...DEFAULT_MACH_LOOKUPS.filter((name) => name !== 'com.apple.SecurityServer').map(
      (name) => `  (global-name ${escapeSeatbelt(name)})`,
    ),
    ')',
    ...generateMachLookupRules(
      network.allowMachLookup,
      allowMachIssueExtension,
    ),
    '',
    '; POSIX IPC',
    '(allow ipc-posix-shm)',
    '(allow ipc-posix-sem)',
    '',
    '; IOKit',
    ...generateIokitRules(system),
    '',
    '; Safe system sockets',
    '(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))',
    '',
    '; sysctl',
    ...generateSysctlReadRules(system.allowSysctlRead),
    '(allow sysctl-write (sysctl-name "kern.tcsm_enable"))',
    '',
    '; Notifications',
    '(allow distributed-notification-post)',
    '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
    '',
    '; Device files',
    ...generateFileIoctlRules(system),
    '',
    '; Network',
  ]

  if (config.networkUnrestricted) {
    profile.push('(allow network*)')
  } else {
    if (network.allowLocalBinding) {
      profile.push('(allow network-bind (local ip "localhost:*"))')
      profile.push('(allow network-inbound (local ip "localhost:*"))')
    }

    profile.push(...generateLoopbackOutboundRules(network))

    if (httpProxyPort) {
      profile.push(`(allow network-bind (local ip "localhost:${httpProxyPort}"))`)
      profile.push(
        `(allow network-inbound (local ip "localhost:${httpProxyPort}"))`,
      )
      profile.push(
        `(allow network-outbound (remote ip "localhost:${httpProxyPort}"))`,
      )
    }

    if (socksProxyPort) {
      profile.push(
        `(allow network-bind (local ip "localhost:${socksProxyPort}"))`,
      )
      profile.push(
        `(allow network-inbound (local ip "localhost:${socksProxyPort}"))`,
      )
      profile.push(
        `(allow network-outbound (remote ip "localhost:${socksProxyPort}"))`,
      )
    }

    profile.push(...generateUnixSocketRules(network.allowUnixSockets, cwd))
  }

  profile.push('', '; File read')
  profile.push(
    ...generateReadRules(
      filesystem,
      filesystem.allowWrite || [],
      logTag,
      cwd,
      allowFileIssueExtension,
      guardRunDir,
      projectDir,
    ),
  )
  profile.push('', '; File write')
  profile.push(
    ...generateWriteRules(
      filesystem,
      logTag,
      cwd,
      allowFileIssueExtension,
    ),
  )

  if (config.allowPty) {
    profile.push('', '; Pseudo-terminal support')
    profile.push('(allow pseudo-tty)')
    profile.push('(allow file-ioctl')
    profile.push('  (literal "/dev/ptmx")')
    profile.push('  (regex #"^/dev/ttys")')
    profile.push(')')
    profile.push('(allow file-read* file-write*')
    profile.push('  (literal "/dev/ptmx")')
    profile.push('  (regex #"^/dev/ttys")')
    profile.push(')')
  }

  return `${profile.join('\n')}\n`
}
