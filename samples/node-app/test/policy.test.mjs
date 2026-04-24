import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createServer as createHttpServer } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { generateProfile } from '../../../lib/guard-manager.mjs'
import { createDomainFilter, buildProxyEnv } from '../../../lib/guard-network.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const appRoot = resolve(__dirname, '..')
const repoRoot = resolve(appRoot, '../..')
const guard = resolve(repoRoot, 'bin/guard')
const shim = resolve(repoRoot, 'bin/guard-shim')

const runGuard = (args, extraEnv = {}) => {
  return spawnSync(guard, ['node', 'scripts/probe.mjs', ...args], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...extraEnv,
      GUARD_QUIET: '1',
    },
  })
}

const runGuardFrom = (cwd, args, extraEnv = {}) => {
  return spawnSync(guard, ['node', resolve(appRoot, 'scripts/probe.mjs'), ...args], {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...extraEnv,
      GUARD_QUIET: '1',
    },
  })
}

const runGuardCommand = (args, extraEnv = {}) => {
  return spawnSync(guard, args, {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...extraEnv,
      GUARD_QUIET: '1',
    },
  })
}

const runGuardCommandAsync = (args, extraEnv = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(guard, args, {
      cwd: appRoot,
      env: {
        ...process.env,
        ...extraEnv,
        GUARD_QUIET: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', reject)
    child.on('close', (status, signal) => {
      resolve({ status, signal, stdout, stderr })
    })
  })

const expectOk = (result) => {
  assert.equal(result.status, 0, result.stderr || result.stdout)
}

const expectDenied = (result) => {
  assert.notEqual(result.status, 0, 'command unexpectedly succeeded')
  assert.match(`${result.stderr}\n${result.stdout}`, /EPERM|operation not permitted|permission/i)
}

const networkProfileConfig = ({
  allowedDomains = ['localhost'],
  deniedDomains = [],
} = {}) => ({
  allowPty: true,
  network: {
    allowedDomains,
    deniedDomains,
    allowLocalBinding: false,
    allowLoopbackConnections: false,
    allowLoopbackHighPorts: false,
    allowLoopbackPorts: [],
    allowUnixSockets: ['${GUARD_RUN_DIR}'],
    allowMachLookup: [
      'com.apple.FSEvents',
      'com.apple.fseventsd',
      'com.apple.FileCoordination',
    ],
  },
  filesystem: {
    denyRead: ['/Users', '/Volumes', '/Applications', '/cores', '/home'],
    allowRead: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
    allowWrite: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
    denyWrite: ['.env', '.env.*', 'secrets/', '*.key', '*.pem'],
  },
})

const ironProxyNetworkProfileConfig = ({ ask = false, httpRules = [] } = {}) => ({
  ...networkProfileConfig({ allowedDomains: [] }),
  network: {
    ...networkProfileConfig({ allowedDomains: [] }).network,
    backend: 'iron-proxy',
    ask,
    httpRules,
  },
})

const writeGuardProfile = (name, cfg) => {
  const profilePath = resolve(appRoot, `.guard/${name}.json`)
  writeFileSync(profilePath, `${JSON.stringify(cfg, null, 2)}\n`)
  return profilePath
}

const closeServer = (server) =>
  new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  )

const listenLoopback = async (server) => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return server.address().port
}

const firstExisting = (candidates) =>
  candidates.find((candidate) => candidate && existsSync(candidate)) || null

const expectNoDirectNetwork = (result) => {
  assert.notEqual(result.status, 0, 'direct network unexpectedly succeeded')
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /EPERM|operation not permitted|permission|not permitted|denied/i,
  )
}

const startGuarddForTest = async ({ policyRoot, eventLog, token = 'test-token', extraArgs = [] }) => {
  let child = null
  const ready = new Promise((resolveReady, rejectReady) => {
    child = spawn(process.execPath, [
      resolve(repoRoot, 'daemon/guardd.mjs'),
      '--port',
      '0',
      '--policy-root',
      policyRoot,
      '--event-log',
      eventLog,
      '--api-token',
      token,
      '--poll-ms',
      '100',
      ...extraArgs,
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_QUIET: '1',
      },
    })
    let stderr = ''
    const timer = setTimeout(() => rejectReady(new Error(`guardd did not start: ${stderr}`)), 5000)
    child.stderr.on('data', (chunk) => {
      stderr += chunk
      const match = stderr.match(/http:\/\/127\.0\.0\.1:(\d+)/)
      if (match) {
        clearTimeout(timer)
        resolveReady(Number(match[1]))
      }
    })
    child.on('error', rejectReady)
    child.on('exit', (code) => {
      if (!stderr.match(/http:\/\/127\.0\.0\.1:(\d+)/)) {
        clearTimeout(timer)
        rejectReady(new Error(`guardd exited before ready: ${code} ${stderr}`))
      }
    })
  })

  const port = await ready
  return {
    child,
    base: `http://127.0.0.1:${port}`,
    token,
    async stop() {
      if (!child) return
      child.kill('SIGTERM')
      await Promise.race([
        new Promise((resolveDone) => child.once('exit', resolveDone)),
        new Promise((resolveDone) => setTimeout(resolveDone, 1000)),
      ])
      child = null
    },
  }
}

for (const [tool, pattern] of [
  ['node', /^v\d+\./],
  ['python', /^Python \d+\./],
  ['python3', /^Python \d+\./],
  ['pip', /^pip \d+\./],
  ['pip3', /^pip \d+\./],
]) {
  test(`${tool} shim wraps configured projects without recursion`, () => {
    const result = spawnSync(shim, ['--version'], {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_QUIET: '1',
        GUARD_BIN: guard,
        GUARD_SHIM_TOOL: tool,
        GUARD_SHIM_BYPASS: '',
        NODE_GUARD_BYPASS: '',
        PNPM_GUARD_BYPASS: '',
        NPM_GUARD_BYPASS: '',
        PYTHON_GUARD_BYPASS: '',
        PYTHON3_GUARD_BYPASS: '',
        PIP_GUARD_BYPASS: '',
        PIP3_GUARD_BYPASS: '',
        DENO_GUARD_BYPASS: '',
      },
    })

    expectOk(result)
    assert.match(result.stdout.trim(), pattern)
  })
}

for (const [tool, pattern] of [
  ['pnpm', /^\d+\./],
  ['npm', /^\d+\./],
]) {
  test(`${tool} shim has an explicit bypass for tool self-hosting paths`, () => {
    const result = spawnSync(shim, ['--version'], {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_BIN: guard,
        GUARD_SHIM_TOOL: tool,
        GUARD_SHIM_BYPASS: '1',
      },
    })

    expectOk(result)
    assert.match(result.stdout.trim(), pattern)
  })
}

test('node shim refuses unconfigured code directories in non-interactive shells', () => {
  const result = spawnSync(shim, ['--version'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      GUARD_BIN: guard,
      GUARD_SHIM_TOOL: 'node',
      NODE_GUARD_BYPASS: '',
    },
  })

  assert.equal(result.status, 130)
  assert.match(result.stderr, /refusing unsandboxed node/)
})

for (const tool of ['npx', 'corepack']) {
  test(`${tool} shim is disabled`, () => {
    const result = spawnSync(shim, ['--version'], {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_BIN: guard,
        GUARD_SHIM_TOOL: tool,
        GUARD_SHIM_BYPASS: '',
      },
    })

    assert.equal(result.status, 1)
    assert.match(result.stderr, new RegExp(`${tool} is disabled by guard`))
  })
}

test('deno shim is disabled until the native macOS runtime supports it', () => {
  const result = spawnSync(shim, ['--version'], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      GUARD_BIN: guard,
      GUARD_SHIM_TOOL: 'deno',
      GUARD_SHIM_BYPASS: '',
    },
  })

  assert.equal(result.status, 1)
  assert.match(result.stderr, /deno is not supported by guard's native macOS runtime yet/)
})

test('can read files inside the allowed project root', () => {
  expectOk(runGuard(['read-file', 'package.json']))
})

test('can start the macOS Node file watcher inside the allowed project root', () => {
  const result = runGuard(['fs-watch', '.'])
  expectOk(result)
  assert.match(result.stdout, /watch-ok/)
})

test('resolves project root placeholders when invoked from a subdirectory', () => {
  const nestedDir = resolve(appRoot, 'nested/invocation')
  mkdirSync(nestedDir, { recursive: true })

  expectOk(runGuardFrom(nestedDir, ['read-file', resolve(appRoot, 'package.json')]))

  const result = runGuardFrom(nestedDir, ['env-json'])
  expectOk(result)
  const env = JSON.parse(result.stdout)
  assert.equal(env.guardProjectDir, appRoot)
  assert.equal(env.guardCwd, nestedDir)
  assert.match(env.guardRunDir, /\/guard\/run-/)
})

test('default built-in profile runs without exposing the invoking home tree', () => {
  const result = spawnSync(
    guard,
    [
      'node',
      '-e',
      [
        "const fs = require('node:fs')",
        "console.log(`cwd=${process.cwd()}`)",
        "console.log(`project=${process.env.GUARD_PROJECT_DIR}`)",
        `fs.readFileSync(${JSON.stringify(resolve(repoRoot, 'package.json'))})`,
      ].join(';'),
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_QUIET: '1',
      },
    },
  )

  assert.notEqual(result.status, 0, 'home-backed package.json read unexpectedly succeeded')
  assert.match(result.stdout, /cwd=\/private\/tmp\/guard\/run-/)
  assert.match(result.stdout, /project=\s*$/m)
  assert.match(`${result.stderr}\n${result.stdout}`, /EPERM|operation not permitted|permission/i)
})

test('generates the expected effective sandbox config', () => {
  const result = runGuard(['runtime-config-json'])
  expectOk(result)
  const cfg = JSON.parse(result.stdout)

  assert.equal(cfg.allowPty, true)
  assert.deepEqual(cfg.filesystem.denyRead, [
    '/Users',
    '/Volumes',
    '/Applications',
    '/cores',
    '/home',
  ])
  assert.equal(cfg.filesystem.allowRead[0], appRoot)
  assert.match(cfg.filesystem.allowRead[1], /\/guard\/run-/)
  assert.equal(cfg.filesystem.allowWrite[0], appRoot)
  assert.match(cfg.filesystem.allowWrite[1], /\/guard\/run-/)
  assert.deepEqual(cfg.filesystem.denyWrite, ['.env', '.env.*', 'secrets/', '*.key', '*.pem'])
  assert.deepEqual(cfg.network.allowedDomains, [])
  assert.equal(cfg.network.allowLocalBinding, true)
  assert.equal(cfg.network.allowLoopbackConnections, false)
  assert.equal(cfg.network.allowLoopbackHighPorts, false)
  assert.deepEqual(cfg.network.allowLoopbackPorts, [3000, 3001, 4983])
  assert.match(cfg.network.allowUnixSockets[0], /\/guard\/run-/)
})

test('profile imports merge named template fragments', () => {
  const profilePath = writeGuardProfile('import-merge', {
    imports: ['node-app-defaults', 'cloudflare-wrangler'],
    network: {
      allowedDomains: ['akcvwaclnbxroirpbesp.supabase.co'],
      allowLoopbackPorts: [54321],
    },
  })

  try {
    const result = runGuardCommand([
      '--profile',
      'import-merge',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.deepEqual(cfg.filesystem.denyRead, [
      '/Users',
      '/Volumes',
      '/Applications',
      '/cores',
      '/home',
    ])
    assert.deepEqual(cfg.network.allowLoopbackPorts, [
      3000,
      3001,
      4983,
      8787,
      8788,
      8976,
      54321,
    ])
    assert.deepEqual(cfg.network.allowedDomains, [
      'api.cloudflare.com',
      '*.cloudflare.com',
      '*.workers.dev',
      '*.pages.dev',
      'akcvwaclnbxroirpbesp.supabase.co',
    ])
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('homeLinks materialize narrow real paths inside the fake home', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-home-link-'))
  const sourceDir = resolve(tempRoot, 'real-config')
  mkdirSync(sourceDir, { recursive: true })
  writeFileSync(resolve(sourceDir, 'default.toml'), 'token = "test"\n')
  const profilePath = writeGuardProfile('home-link', {
    ...networkProfileConfig({ allowedDomains: [] }),
    filesystem: {
      ...networkProfileConfig({ allowedDomains: [] }).filesystem,
      allowRead: [
        '${GUARD_PROJECT_DIR}',
        '${GUARD_RUN_DIR}',
        sourceDir,
      ],
    },
    homeLinks: [
      {
        source: sourceDir,
        target: 'Library/Preferences/.wrangler/config',
      },
    ],
  })

  try {
    const result = runGuardCommand([
      '--profile',
      'home-link',
      'node',
      'scripts/probe.mjs',
      'read-home-link',
      'Library/Preferences/.wrangler/config/default.toml',
    ])
    expectOk(result)
    assert.equal(result.stdout, 'token = "test"\n')
  } finally {
    rmSync(profilePath, { force: true })
    rmSync(tempRoot, { force: true, recursive: true })
  }
})

test('allowLocalBinding emits loopback bind rules without direct outbound access', () => {
  const profile = generateProfile(
    {
      network: {
        allowLocalBinding: true,
      },
    },
    { cwd: appRoot },
  )

  assert.match(profile, /\(allow network-bind \(local ip "localhost:\*"\)\)/)
  assert.match(profile, /\(allow network-inbound \(local ip "localhost:\*"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(local ip "\*:\*"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "localhost:\*"\)\)/)
})

test('allowLoopbackConnections emits loopback outbound without broad egress', () => {
  const profile = generateProfile(
    {
      network: {
        allowLoopbackConnections: true,
      },
    },
    { cwd: appRoot },
  )

  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:\*"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "\*:\*"\)\)/)
})

test('allowLoopbackPorts emits exact loopback outbound ports only', () => {
  const profile = generateProfile(
    {
      network: {
        allowLoopbackPorts: [3001, '4983', 3001],
      },
    },
    { cwd: appRoot },
  )

  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:3001"\)\)/)
  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:4983"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "localhost:\*"\)\)/)
})

test('allowedRawTcp resolved loopback rules emit exact localhost port only', () => {
  const profile = generateProfile(
    {
      network: {},
    },
    {
      cwd: appRoot,
      resolvedRawTcpRules: [
        { ip: '127.0.0.1', port: '2222' },
        { ip: '::1', port: 2223 },
      ],
    },
  )

  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:2222"\)\)/)
  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:2223"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "localhost:\*"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "\*:\*"\)\)/)
})

test('allowedRawTcp rejects exact external raw TCP under sandbox-exec', () => {
  assert.throws(
    () =>
      generateProfile(
        {
          network: {},
        },
        {
          cwd: appRoot,
          resolvedRawTcpRules: [{ ip: '16.16.87.224', port: 22 }],
        },
      ),
    /exact external IP rules are not supported/,
  )
})

test('buildProxyEnv exposes reusable SOCKS and SSH proxy environment', () => {
  const env = buildProxyEnv({ httpPort: 18080, socksPort: 19090 })

  assert.ok(env.includes('GUARD_SOCKS_PROXY=localhost:19090'))
  assert.ok(env.includes('GUARD_SSH_PROXY_COMMAND=nc -X 5 -x localhost:19090 %h %p'))
  assert.ok(env.includes("GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x localhost:19090 %h %p'"))
})

test('allowLoopbackHighPorts emits the macOS ephemeral range only', () => {
  const profile = generateProfile(
    {
      network: {
        allowLoopbackHighPorts: true,
      },
    },
    { cwd: appRoot },
  )

  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:49152"\)\)/)
  assert.match(profile, /\(allow network-outbound \(remote ip "localhost:65535"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "localhost:49151"\)\)/)
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote ip "localhost:\*"\)\)/)
})

test('version probes keep filesystem sandbox while skipping expensive high-port network rules', () => {
  const profilePath = writeGuardProfile('version-probe-high-ports', {
    ...networkProfileConfig({
      allowedDomains: ['example.com'],
    }),
    network: {
      ...networkProfileConfig({ allowedDomains: ['example.com'] }).network,
      allowLoopbackHighPorts: true,
      allowLoopbackPorts: [3000],
    },
  })
  const tempDir = mkdtempSync(join(tmpdir(), 'guard-version-probe-'))
  const pnpmLikeNode = join(tempDir, 'pnpm.cjs')

  try {
    symlinkSync(process.execPath, pnpmLikeNode)

    for (const command of [
      ['node', '--version'],
      [pnpmLikeNode, '--version'],
    ]) {
      const result = spawnSync(
        guard,
        ['--profile', 'version-probe-high-ports', ...command],
        {
          cwd: appRoot,
          encoding: 'utf8',
          env: {
            ...process.env,
            GUARD_BANNER: 'compact',
            GUARD_QUIET: '',
          },
        },
      )

      expectOk(result)
      assert.match(result.stdout.trim(), /^v\d+\./)

      const runMatch = result.stderr.match(/run=([^\s]+)/)
      assert.ok(runMatch, result.stderr)
      const generatedProfile = readFileSync(
        join(runMatch[1], 'tmp/profile.sb'),
        'utf8',
      )

      assert.match(generatedProfile, /\(deny file-read\*[\s\S]*\(subpath "\/Users"\)/)
      assert.doesNotMatch(generatedProfile, /localhost:49152/)
      assert.doesNotMatch(generatedProfile, /localhost:3000/)
      assert.doesNotMatch(generatedProfile, /example\.com/)
    }
  } finally {
    rmSync(profilePath, { force: true })
    rmSync(tempDir, { force: true, recursive: true })
  }
})

test('allowLoopbackPorts rejects invalid ports', () => {
  assert.throws(
    () =>
      generateProfile(
        {
          network: {
            allowLoopbackPorts: [0],
          },
        },
        { cwd: appRoot },
      ),
    /invalid network\.allowLoopbackPorts entry/,
  )
})

test('native manager does not emit extension rules by default', () => {
  const profile = generateProfile(
    {
      networkUnrestricted: true,
      network: {
        allowMachLookup: ['com.apple.webinspector'],
      },
      filesystem: {
        denyRead: ['/Users'],
        allowRead: ['/tmp/zoom-read'],
        allowWrite: ['/tmp/zoom-write'],
        denyWrite: [],
      },
    },
    { cwd: appRoot },
  )

  assert.doesNotMatch(profile, /file-issue-extension/)
  assert.doesNotMatch(profile, /mach-issue-extension/)
})

test('native manager defaults denyRead to critical roots and reopens project root plus guard run dir', () => {
  const nestedDir = resolve(appRoot, 'nested/invocation')
  const profile = generateProfile(
    {
      networkUnrestricted: true,
    },
    {
      cwd: nestedDir,
      projectDir: appRoot,
      guardRunDir: '/private/tmp/guard/default-run',
    },
  )

  assert.match(profile, /\(deny file-read\*[\s\S]*\(subpath "\/Users"\)/)
  assert.match(profile, /\(deny file-read\*[\s\S]*\(subpath "\/Volumes"\)/)
  assert.match(
    profile,
    new RegExp(
      `\\(allow file-read\\*[\\s\\S]*\\(subpath "${appRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\)`,
    ),
  )
  assert.doesNotMatch(
    profile,
    new RegExp(
      `\\(allow file-read\\*[\\s\\S]*\\(subpath "${nestedDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\)`,
    ),
  )
  assert.match(
    profile,
    /\(allow file-read\*[\s\S]*\(subpath "\/private\/tmp\/guard\/default-run"\)/,
  )
})

test('missing filesystem config defaults allowRead to project root from nested invocations', () => {
  const profilePath = resolve(appRoot, '.guard/defaults.json')
  try {
    writeFileSync(
      profilePath,
      JSON.stringify(
        {
          allowPty: true,
          network: {
            allowedDomains: [],
            deniedDomains: [],
            allowLocalBinding: true,
            allowUnixSockets: ['${GUARD_RUN_DIR}'],
          },
        },
        null,
        2,
      ) + '\n',
    )

    const nestedDir = resolve(appRoot, 'nested/invocation')
    mkdirSync(nestedDir, { recursive: true })
    const result = spawnSync(
      guard,
      [
        '--profile',
        'defaults',
        'node',
        resolve(appRoot, 'scripts/probe.mjs'),
        'runtime-config-json',
      ],
      {
        cwd: nestedDir,
        encoding: 'utf8',
        env: {
          ...process.env,
          GUARD_QUIET: '1',
        },
      },
    )

    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.filesystem.allowRead[0], appRoot)
    assert.match(cfg.filesystem.allowRead[1], /\/guard\/run-/)
    assert.deepEqual(cfg.filesystem.denyRead, [
      '/Users',
      '/Volumes',
      '/Applications',
      '/cores',
      '/home',
    ])
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('native manager emits extension rules only when explicitly enabled', () => {
  const profile = generateProfile(
    {
      networkUnrestricted: true,
      network: {
        allowMachLookup: ['com.apple.webinspector', 'us.zoom.aom.globalmgr.*'],
      },
      filesystem: {
        denyRead: ['/Users'],
        allowRead: ['/tmp/zoom-read', '/tmp/zoom-read-glob/*'],
        allowWrite: ['/tmp/zoom-write', '/tmp/zoom-write-glob/*'],
        denyWrite: [],
      },
      system: {
        allowFileIssueExtension: true,
        allowMachIssueExtension: true,
        allowSysctlRead: ['hw.model', 'kern.proc.*'],
        allowIokitUserClientClass: ['AGXDeviceUserClient'],
      },
    },
    { cwd: appRoot },
  )

  assert.match(
    profile,
    /\(allow mach-issue-extension \(global-name "com\.apple\.webinspector"\)\)/,
  )
  assert.match(
    profile,
    /\(allow mach-issue-extension \(global-name-prefix "us\.zoom\.aom\.globalmgr\."\)\)/,
  )
  assert.match(
    profile,
    /\(allow file-issue-extension[\s\S]*\(subpath "\/tmp\/zoom-read"\)/,
  )
  assert.match(
    profile,
    /\(allow file-issue-extension[\s\S]*\(subpath "\/tmp\/zoom-write"\)/,
  )
  assert.match(profile, /\(allow sysctl-read \(sysctl-name "hw\.model"\)\)/)
  assert.match(
    profile,
    /\(allow sysctl-read \(sysctl-name-prefix "kern\.proc\."\)\)/,
  )
  assert.match(
    profile,
    /\(iokit-user-client-class "AGXDeviceUserClient"\)/,
  )
})

test('accepts -- as a command separator', () => {
  const result = spawnSync(guard, ['--', 'node', 'scripts/probe.mjs', 'env-json'], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      GUARD_QUIET: '1',
    },
  })

  expectOk(result)
  const env = JSON.parse(result.stdout)
  assert.equal(env.guardProjectDir, appRoot)
})

test('--deep-egress forces the iron-proxy backend for a run', () => {
  const profilePath = writeGuardProfile(
    'deep-egress-flag',
    networkProfileConfig({ allowedDomains: [] }),
  )

  try {
    const result = runGuardCommand([
      '--deep-egress',
      '--ask-network',
      '--profile',
      'deep-egress-flag',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.network.backend, 'iron-proxy')
    assert.equal(cfg.network.ask, true)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('--deep-egress can run with the built-in guard profile outside a project config', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-deep-egress-'))
  try {
    const result = spawnSync(
      guard,
      ['--deep-egress', '--ask-network', '--profile', 'guard', '/usr/bin/true'],
      {
        cwd: tempRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          GUARD_QUIET: '1',
        },
      },
    )
    expectOk(result)
  } finally {
    rmSync(tempRoot, { force: true, recursive: true })
  }
})

test('allowedDomains permits allowlisted HTTP traffic through the local proxy runtime', async () => {
  const profilePath = resolve(appRoot, '.guard/network-allow.json')
  writeFileSync(
    profilePath,
    JSON.stringify(
      {
        allowPty: true,
        network: {
          allowedDomains: ['localhost'],
          deniedDomains: [],
          allowLocalBinding: false,
          allowUnixSockets: ['${GUARD_RUN_DIR}'],
          allowMachLookup: [
            'com.apple.FSEvents',
            'com.apple.fseventsd',
            'com.apple.FileCoordination',
          ],
        },
        filesystem: {
          denyRead: ['/Users', '/Volumes', '/Applications', '/cores', '/home'],
          allowRead: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
          allowWrite: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
          denyWrite: ['.env', '.env.*', 'secrets/', '*.key', '*.pem'],
        },
      },
      null,
      2,
    ) + '\n',
  )

  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('network-ok\n')
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  const url = `http://localhost:${address.port}/`

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-allow',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      url,
    ])
    expectOk(result)
    assert.match(result.stdout, /network-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    )
  }
})

test('allowedDomains blocks non-allowlisted HTTP traffic through the local proxy runtime', async () => {
  const profilePath = resolve(appRoot, '.guard/network-block.json')
  writeFileSync(
    profilePath,
    JSON.stringify(
      {
        allowPty: true,
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          allowLocalBinding: false,
          allowUnixSockets: ['${GUARD_RUN_DIR}'],
          allowMachLookup: [
            'com.apple.FSEvents',
            'com.apple.fseventsd',
            'com.apple.FileCoordination',
          ],
        },
        filesystem: {
          denyRead: ['/Users', '/Volumes', '/Applications', '/cores', '/home'],
          allowRead: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
          allowWrite: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
          denyWrite: ['.env', '.env.*', 'secrets/', '*.key', '*.pem'],
        },
      },
      null,
      2,
    ) + '\n',
  )

  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  const url = `http://localhost:${address.port}/`

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-block',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      url,
    ])
    assert.notEqual(result.status, 0)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|blocked/i)
  } finally {
    rmSync(profilePath, { force: true })
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    )
  }
})

test('deniedDomains overrides allowedDomains in the proxy runtime', async () => {
  const profilePath = writeGuardProfile(
    'network-denied-overrides',
    networkProfileConfig({
      allowedDomains: ['localhost'],
      deniedDomains: ['localhost'],
    }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-denied-overrides',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/`,
    ])
    assert.notEqual(result.status, 0)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|blocked/i)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('iron-proxy backend permits matching HTTP method and path rules', async () => {
  const profilePath = writeGuardProfile(
    'network-iron-allow',
    ironProxyNetworkProfileConfig({
      httpRules: [
        {
          host: 'localhost',
          methods: ['GET'],
          paths: ['/allowed'],
        },
      ],
    }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`iron-ok ${req.method} ${req.url}\n`)
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-allow',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/allowed`,
    ])
    expectOk(result)
    assert.equal(result.stdout, 'iron-ok GET /allowed\n')
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('iron-proxy backend blocks non-matching HTTP paths', async () => {
  const profilePath = writeGuardProfile(
    'network-iron-block-path',
    ironProxyNetworkProfileConfig({
      httpRules: [
        {
          host: 'localhost',
          methods: ['GET'],
          paths: ['/allowed'],
        },
      ],
    }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-block-path',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/blocked`,
    ])
    assert.notEqual(result.status, 0)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|Forbidden/i)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('iron-proxy backend blocks non-matching HTTP methods', async () => {
  const profilePath = writeGuardProfile(
    'network-iron-block-method',
    ironProxyNetworkProfileConfig({
      httpRules: [
        {
          host: 'localhost',
          methods: ['GET'],
          paths: ['/allowed'],
        },
      ],
    }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-block-method',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      '-X',
      'POST',
      `http://localhost:${port}/allowed`,
    ])
    assert.notEqual(result.status, 0)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|Forbidden/i)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('iron-proxy interactive backend denies unknown requests in non-interactive shells', async () => {
  const profilePath = writeGuardProfile(
    'network-iron-ask-noninteractive',
    ironProxyNetworkProfileConfig({ ask: true }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-ask-noninteractive',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/unknown`,
    ])
    assert.notEqual(result.status, 0)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|Forbidden/i)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('iron-proxy backend supports fetch, curl, npm, and pnpm clients', async () => {
  const npmBin = firstExisting([
    process.env.GUARD_REAL_NPM,
    '/opt/homebrew/bin/npm',
    '/usr/local/bin/npm',
    process.env.HOME ? join(process.env.HOME, '.local/bin/npm') : null,
  ])
  const pnpmBin = firstExisting([
    process.env.GUARD_REAL_PNPM,
    '/opt/homebrew/bin/pnpm',
    '/usr/local/bin/pnpm',
    process.env.HOME ? join(process.env.HOME, '.local/bin/pnpm') : null,
  ])
  if (!npmBin || !pnpmBin) {
    return
  }

  const profilePath = writeGuardProfile(
    'network-iron-clients',
    ironProxyNetworkProfileConfig({
      httpRules: [
        {
          host: 'localhost',
          methods: ['GET'],
          paths: ['/fetch', '/curl', '/guard-proxy-test', '/guard-proxy-test/*'],
        },
      ],
    }),
  )
  const server = createHttpServer((req, res) => {
    if ((req.url || '').startsWith('/guard-proxy-test')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        name: 'guard-proxy-test',
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            name: 'guard-proxy-test',
            version: '1.0.0',
            dist: {
              tarball: 'http://localhost/guard-proxy-test/-/guard-proxy-test-1.0.0.tgz',
              shasum: '0000000000000000000000000000000000000000',
            },
          },
        },
      }))
      return
    }
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`iron-client-ok ${req.url}\n`)
  })
  const port = await listenLoopback(server)
  const registry = `http://localhost:${port}`

  try {
    const fetchResult = await runGuardCommandAsync([
      '--profile',
      'network-iron-clients',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      'node',
      'scripts/probe.mjs',
      'node-fetch',
      `${registry}/fetch`,
    ])
    expectOk(fetchResult)
    assert.equal(fetchResult.stdout, 'iron-client-ok /fetch\n')

    const curl = await runGuardCommandAsync([
      '--profile',
      'network-iron-clients',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `${registry}/curl`,
    ])
    expectOk(curl)
    assert.equal(curl.stdout, 'iron-client-ok /curl\n')

    const npm = await runGuardCommandAsync([
      '--profile',
      'network-iron-clients',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      npmBin,
      'view',
      'guard-proxy-test',
      'version',
      '--registry',
      registry,
      '--fetch-retries',
      '0',
      '--fetch-timeout',
      '5000',
    ])
    expectOk(npm)
    assert.match(npm.stdout, /1\.0\.0/)

    const pnpm = await runGuardCommandAsync([
      '--profile',
      'network-iron-clients',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      pnpmBin,
      'view',
      'guard-proxy-test',
      'version',
      '--registry',
      registry,
    ])
    expectOk(pnpm)
    assert.match(pnpm.stdout, /1\.0\.0/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('network ask filter prompts once and caches allowed hosts for the run', async () => {
  const prompts = []
  const filter = createDomainFilter(
    {
      allowedDomains: [],
      deniedDomains: [],
    },
    {
      ask: async (host, port) => {
        prompts.push({ host, port })
        return true
      },
    },
  )

  assert.equal(await filter('LOCALHOST', 8080), true)
  assert.equal(await filter('localhost', 9090), true)
  assert.deepEqual(prompts, [{ host: 'localhost', port: 8080 }])
})

test('network ask does not prompt for denied domains', async () => {
  let prompted = false
  const filter = createDomainFilter(
    {
      allowedDomains: [],
      deniedDomains: ['localhost'],
    },
    {
      ask: async () => {
        prompted = true
        return true
      },
    },
  )

  assert.equal(await filter('localhost', 8080), false)
  assert.equal(prompted, false)
})

test('network ask blocks unknown hosts in non-interactive shells', async () => {
  const profilePath = writeGuardProfile(
    'network-ask-noninteractive',
    networkProfileConfig({ allowedDomains: [] }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--ask-network',
      '--profile',
      'network-ask-noninteractive',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/`,
    ])
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /--ask-network requires an interactive terminal/)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|blocked/i)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('HTTPS CONNECT tunnels are filtered by allowedDomains', async () => {
  const profilePath = writeGuardProfile('network-connect', networkProfileConfig())
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('connect-ok\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-connect',
      'node',
      'scripts/probe.mjs',
      'http-connect',
      `http://localhost:${port}/connect`,
    ])
    expectOk(result)
    assert.match(result.stdout, /connect-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('SOCKS proxy tunnels are filtered by allowedDomains', async () => {
  const profilePath = writeGuardProfile('network-socks', networkProfileConfig())
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('socks-ok\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-socks',
      'node',
      'scripts/probe.mjs',
      'socks-http',
      `http://localhost:${port}/socks`,
    ])
    expectOk(result)
    assert.match(result.stdout, /socks-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('default local binding policy allows loopback TCP listeners', () => {
  const result = runGuard(['tcp-listen', '127.0.0.1'])
  expectOk(result)
  assert.match(result.stdout, /listen-ok/)
})

test('allowLoopbackPorts policy allows exact loopback TCP connections', async () => {
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('loopback-ok\n')
  })
  const port = await listenLoopback(server)
  const profilePath = writeGuardProfile('network-loopback-port', {
    ...networkProfileConfig({ allowedDomains: [] }),
    network: {
      ...networkProfileConfig({ allowedDomains: [] }).network,
      allowLoopbackPorts: [port],
    },
  })

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-loopback-port',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      `tcp://127.0.0.1:${port}`,
    ])
    expectOk(result)
    assert.match(result.stdout, /direct-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('allowLoopbackListeningHighPorts allows already-listening high loopback ports', async () => {
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('listening-high-ok\n')
  })
  const port = await listenLoopback(server)
  assert.ok(port >= 49152, `expected an ephemeral port, got ${port}`)

  const cfg = networkProfileConfig({ allowedDomains: [] })
  cfg.network.allowLoopbackListeningHighPorts = ['node']
  cfg.network.allowLoopbackPorts = []
  const profilePath = writeGuardProfile('network-loopback-listening-high', cfg)

  try {
    const configResult = runGuardCommand([
      '--profile',
      'network-loopback-listening-high',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(configResult)
    const runtimeCfg = JSON.parse(configResult.stdout)
    assert.equal(runtimeCfg.network.allowLoopbackHighPorts, false)
    assert.ok(runtimeCfg.network.allowLoopbackPorts.includes(port))

    const connectResult = await runGuardCommandAsync([
      '--profile',
      'network-loopback-listening-high',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      `tcp://127.0.0.1:${port}`,
    ])
    expectOk(connectResult)
    assert.match(connectResult.stdout, /direct-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('default local binding policy allows IPv6 loopback TCP listeners', () => {
  const result = runGuard(['tcp-listen', '::1'])
  expectOk(result)
  assert.match(result.stdout, /listen-ok/)
})

test('default local binding policy denies direct external TCP egress', () => {
  const result = runGuard(['direct-tcp', 'tcp://1.1.1.1:80'])
  expectNoDirectNetwork(result)
})

test('default local binding policy denies direct external IPv6 TCP egress', () => {
  const result = runGuard(['direct-tcp', 'tcp://[2606:4700:4700::1111]:80'])
  expectNoDirectNetwork(result)
})

test('default local binding policy denies direct TCP DNS egress', () => {
  const result = runGuard(['direct-tcp', 'tcp://8.8.8.8:53'])
  expectNoDirectNetwork(result)
})

test('default local binding policy denies direct IPv6 TCP DNS egress', () => {
  const result = runGuard(['direct-tcp', 'tcp://[2001:4860:4860::8888]:53'])
  expectNoDirectNetwork(result)
})

test('default local binding policy denies ICMP egress', () => {
  const ping = firstExisting(['/sbin/ping', '/bin/ping'])
  if (!ping) return

  const result = runGuardCommand([ping, '-c', '1', '-t', '1', '1.1.1.1'])
  expectNoDirectNetwork(result)
})

test('default local binding policy denies ICMPv6 egress', () => {
  const ping6 = firstExisting(['/sbin/ping6', '/bin/ping6'])
  if (!ping6) return

  const result = runGuardCommand([ping6, '-c', '1', '2606:4700:4700::1111'])
  expectNoDirectNetwork(result)
})

test('raw TCP egress is denied when allowedDomains requires the guard proxy', async () => {
  const profilePath = writeGuardProfile('network-direct-deny', networkProfileConfig())
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('direct-should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-direct-deny',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      `tcp://localhost:${port}`,
    ])
    expectDenied(result)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('allowedRawTcp resolveAtLaunch permits only exact direct TCP destinations', async () => {
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('raw-ok\n')
  })
  const port = await listenLoopback(server)
  const profilePath = writeGuardProfile('network-raw-tcp-allow', {
    ...networkProfileConfig({ allowedDomains: [] }),
    network: {
      ...networkProfileConfig({ allowedDomains: [] }).network,
      allowedRawTcp: [
        {
          host: 'localhost',
          resolveAtLaunch: true,
          port,
          reason: 'test exact raw tcp escape hatch',
        },
      ],
    },
  })

  try {
    const allowed = await runGuardCommandAsync([
      '--profile',
      'network-raw-tcp-allow',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      `tcp://127.0.0.1:${port}`,
    ])
    expectOk(allowed)
    assert.match(allowed.stdout, /direct-ok/)

    const denied = await runGuardCommandAsync([
      '--profile',
      'network-raw-tcp-allow',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      `tcp://127.0.0.1:${port + 1}`,
    ])
    expectNoDirectNetwork(denied)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('allowedRawTcp host rules require explicit launch-time resolution', () => {
  const profilePath = writeGuardProfile('network-raw-tcp-host-requires-resolution', {
    ...networkProfileConfig({ allowedDomains: [] }),
    network: {
      ...networkProfileConfig({ allowedDomains: [] }).network,
      allowedRawTcp: [{ host: 'localhost', port: 22 }],
    },
  })

  try {
    const result = runGuardCommand([
      '--profile',
      'network-raw-tcp-host-requires-resolution',
      '/usr/bin/true',
    ])
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /resolveAtLaunch: true/)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('direct TCP DNS egress is denied when allowedDomains requires the guard proxy', () => {
  const profilePath = writeGuardProfile('network-direct-dns-deny', networkProfileConfig())

  try {
    const result = runGuardCommand([
      '--profile',
      'network-direct-dns-deny',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      'tcp://8.8.8.8:53',
    ])
    expectNoDirectNetwork(result)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('direct IPv6 TCP DNS egress is denied when allowedDomains requires the guard proxy', () => {
  const profilePath = writeGuardProfile('network-direct-ipv6-dns-deny', networkProfileConfig())

  try {
    const result = runGuardCommand([
      '--profile',
      'network-direct-ipv6-dns-deny',
      'node',
      'scripts/probe.mjs',
      'direct-tcp',
      'tcp://[2001:4860:4860::8888]:53',
    ])
    expectNoDirectNetwork(result)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('ICMP egress is denied when allowedDomains requires the guard proxy', () => {
  const ping = firstExisting(['/sbin/ping', '/bin/ping'])
  if (!ping) return

  const profilePath = writeGuardProfile('network-icmp-deny', networkProfileConfig())

  try {
    const result = runGuardCommand([
      '--profile',
      'network-icmp-deny',
      ping,
      '-c',
      '1',
      '-t',
      '1',
      '1.1.1.1',
    ])
    expectNoDirectNetwork(result)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('ICMPv6 egress is denied when allowedDomains requires the guard proxy', () => {
  const ping6 = firstExisting(['/sbin/ping6', '/bin/ping6'])
  if (!ping6) return

  const profilePath = writeGuardProfile('network-icmpv6-deny', networkProfileConfig())

  try {
    const result = runGuardCommand([
      '--profile',
      'network-icmpv6-deny',
      ping6,
      '-c',
      '1',
      '2606:4700:4700::1111',
    ])
    expectNoDirectNetwork(result)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('Node fetch uses guard proxy support without a project undici dependency', async () => {
  const profilePath = writeGuardProfile('network-fetch', networkProfileConfig())
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('fetch-ok\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-fetch',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      'node',
      'scripts/probe.mjs',
      'node-fetch',
      `http://localhost:${port}/fetch`,
    ])
    expectOk(result)
    assert.match(result.stdout, /fetch-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('WebSocket clients can connect through the guard HTTP proxy', async () => {
  const profilePath = writeGuardProfile('network-websocket', networkProfileConfig())
  const server = createHttpServer()
  server.on('upgrade', (req, socket) => {
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
    )
    socket.end()
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-websocket',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      'node',
      'scripts/probe.mjs',
      'websocket',
      `ws://localhost:${port}/socket`,
    ])
    expectOk(result)
    assert.match(result.stdout, /websocket-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('npm, pnpm, git, and curl clients use the guard proxy environment', async () => {
  const npmBin = firstExisting([
    process.env.GUARD_REAL_NPM,
    '/opt/homebrew/bin/npm',
    '/usr/local/bin/npm',
    process.env.HOME ? join(process.env.HOME, '.local/bin/npm') : null,
  ])
  const pnpmBin = firstExisting([
    process.env.GUARD_REAL_PNPM,
    '/opt/homebrew/bin/pnpm',
    '/usr/local/bin/pnpm',
    process.env.HOME ? join(process.env.HOME, '.local/bin/pnpm') : null,
  ])
  if (!npmBin || !pnpmBin) {
    return
  }

  const profilePath = writeGuardProfile('network-cli-clients', networkProfileConfig())
  const seen = new Set()
  const server = createHttpServer((req, res) => {
    seen.add(req.url || '/')
    if ((req.url || '').startsWith('/guard-proxy-test')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        name: 'guard-proxy-test',
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            name: 'guard-proxy-test',
            version: '1.0.0',
            dist: {
              tarball: 'http://localhost/guard-proxy-test/-/guard-proxy-test-1.0.0.tgz',
              shasum: '0000000000000000000000000000000000000000',
            },
          },
        },
      }))
      return
    }
    if ((req.url || '').startsWith('/repo.git/info/refs')) {
      res.writeHead(200, {
        'content-type': 'application/x-git-upload-pack-advertisement',
      })
      res.end('001e# service=git-upload-pack\n00000000')
      return
    }
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('cli-ok\n')
  })
  const port = await listenLoopback(server)
  const registry = `http://localhost:${port}`

  try {
    const npm = await runGuardCommandAsync([
      '--profile',
      'network-cli-clients',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      npmBin,
      'view',
      'guard-proxy-test',
      'version',
      '--registry',
      registry,
      '--fetch-retries',
      '0',
      '--fetch-timeout',
      '5000',
    ])
    expectOk(npm)
    assert.match(npm.stdout, /1\.0\.0/)

    const pnpm = await runGuardCommandAsync([
      '--profile',
      'network-cli-clients',
      '/usr/bin/env',
      'NO_PROXY=',
      'no_proxy=',
      pnpmBin,
      'view',
      'guard-proxy-test',
      'version',
      '--registry',
      registry,
    ])
    expectOk(pnpm)
    assert.match(pnpm.stdout, /1\.0\.0/)

    const git = await runGuardCommandAsync([
      '--profile',
      'network-cli-clients',
      '/bin/sh',
      '-c',
      'NO_PROXY= no_proxy= TMPDIR="$GUARD_TMP_DIR" /usr/bin/git ls-remote "$1"',
      'guard-git-test',
      `${registry}/repo.git`,
    ])
    assert.equal(seen.has('/repo.git/info/refs?service=git-upload-pack'), true)
    assert.doesNotMatch(`${git.stderr}\n${git.stdout}`, /Connection refused|network allowlist|blocked/i)

    const curl = await runGuardCommandAsync([
      '--profile',
      'network-cli-clients',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `${registry}/curl`,
    ])
    expectOk(curl)
    assert.match(curl.stdout, /cli-ok/)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('guard backend exposes reusable SOCKS and SSH proxy environment', async () => {
  const profilePath = writeGuardProfile('network-guard-proxy-env', networkProfileConfig())

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-guard-proxy-env',
      'node',
      'scripts/probe.mjs',
      'env-json',
    ])
    expectOk(result)
    const env = JSON.parse(result.stdout)
    assert.match(env.guardSocksProxy, /^localhost:\d+$/)
    assert.match(env.guardSshProxyCommand, /^nc -X 5 -x localhost:\d+ %h %p$/)
    assert.equal(env.allProxy, `socks5h://${env.guardSocksProxy}`)
    assert.equal(
      env.gitSshCommand,
      `ssh -o ProxyCommand='${env.guardSshProxyCommand}'`,
    )
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('iron-proxy backend exposes the same reusable SOCKS and SSH proxy environment', async () => {
  const profilePath = writeGuardProfile(
    'network-iron-proxy-env',
    ironProxyNetworkProfileConfig({
      httpRules: [{ host: 'localhost' }],
    }),
  )

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-proxy-env',
      'node',
      'scripts/probe.mjs',
      'env-json',
    ])
    expectOk(result)
    const env = JSON.parse(result.stdout)
    assert.match(env.guardSocksProxy, /^localhost:\d+$/)
    assert.match(env.guardSshProxyCommand, /^nc -X 5 -x localhost:\d+ %h %p$/)
    assert.equal(env.allProxy, `socks5h://${env.guardSocksProxy}`)
    assert.equal(
      env.gitSshCommand,
      `ssh -o ProxyCommand='${env.guardSshProxyCommand}'`,
    )
  } finally {
    rmSync(profilePath, { force: true })
  }
})

for (const [profile, appPattern] of [
  ['zoom', /\/Applications\/zoom\.us\.app/],
  ['teams', /\/Applications\/Microsoft Teams\.app/],
  ['webex', /\/Applications\/Webex\.app/],
]) {
  test(`loads built-in ${profile} app profile without a project .guard directory`, () => {
    const result = spawnSync(guard, ['--profile', profile], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_COLOR: 'never',
      },
    })

    expectOk(result)
    assert.match(result.stderr, new RegExp(`guard:${profile}`))
    assert.doesNotMatch(result.stderr, /unrestricted/)
    assert.match(result.stderr, /× write\s+.*\/Applications/)

    const cfg = JSON.parse(readFileSync(resolve(repoRoot, `profiles/${profile}.json`), 'utf8'))
    assert.match(cfg.filesystem.allowRead.join('\n'), appPattern)
    assert.match(cfg.network.allowedDomains.join('\n'), /\*/)
  })
}

for (const profile of ['zoom', 'teams', 'webex']) {
  test(`guard run ${profile} launches the built-in app profile`, () => {
    const envName = `GUARD_${profile.toUpperCase()}_BIN`
    const result = spawnSync(guard, ['run', profile, `guard-run-${profile}`], {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        [envName]: '/bin/echo',
        GUARD_QUIET: '1',
      },
    })

    expectOk(result)
    assert.equal(result.stdout.trim(), `guard-run-${profile}`)
  })
}

test('built-in app profiles are locked to vendor allowlists', () => {
  for (const profile of ['zoom', 'teams', 'webex']) {
    const cfg = JSON.parse(readFileSync(resolve(repoRoot, `profiles/${profile}.json`), 'utf8'))
    assert.notEqual(cfg.networkUnrestricted, true)
    assert.ok(cfg.network.allowedDomains.length > 0)
    assert.deepEqual(cfg.filesystem.denyRead, [
      '/Users',
      '/Volumes',
      '/Applications',
      '/cores',
      '/home',
    ])
    assert.ok(cfg.filesystem.allowRead.some((entry) => entry.startsWith('/Applications/')))
    assert.equal(cfg.network.allowLocalBinding, false)
  }
})

test('list profiles reports built-in profiles', () => {
  const result = spawnSync(guard, ['list', 'profiles'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  assert.match(result.stdout, /^Built-in Guard Profiles/m)
  assert.match(result.stdout, /\bzoom\b.*network=allowlist/)
  assert.match(result.stdout, /\bteams\b.*launcher=guard-teams/)
  assert.match(result.stdout, /\bwebex\b.*launcher=guard-webex/)
})

test('guard help prints command usage', () => {
  const result = spawnSync(guard, ['help'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  assert.match(result.stdout, /^Usage:/)
  assert.match(result.stdout, /guard install-apps \[--dir DIR\] \[--force\]/)
  assert.match(result.stdout, /guard monitor-log \[--json\] \[--limit N\] \[PATH\]/)
  assert.match(result.stdout, /guard install-monitor \[--dir DIR\] \[--force\]/)
})

test('list profile can emit machine-readable JSON', () => {
  const result = spawnSync(guard, ['list', 'profile', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const listed = JSON.parse(result.stdout)
  const names = listed.profiles.map((profile) => profile.name)
  assert.deepEqual(names, ['guard', 'teams', 'webex', 'zoom'])
  assert.equal(
    listed.profiles.find((profile) => profile.name === 'teams').launcher,
    'guard-teams',
  )
  assert.equal(
    listed.profiles.find((profile) => profile.name === 'zoom').network,
    'allowlist',
  )
})

test('list templates can emit machine-readable JSON', () => {
  const result = spawnSync(guard, ['list', 'templates', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const listed = JSON.parse(result.stdout)
  assert.deepEqual(
    listed.templates.map((template) => template.name),
    ['cloudflare-wrangler', 'node-app'],
  )

  const wrangler = listed.templates.find((template) => template.name === 'cloudflare-wrangler')
  assert.equal(wrangler.source, 'template')
  assert.equal(wrangler.status, 'template')
  assert.equal(wrangler.risk, 'medium')
  assert.deepEqual(wrangler.imports, ['node-app-defaults', 'cloudflare-wrangler'])
  assert.equal(wrangler.path, resolve(repoRoot, 'templates/cloudflare-wrangler/guard.json'))

  const nodeApp = listed.templates.find((template) => template.name === 'node-app')
  assert.equal(nodeApp.source, 'template')
  assert.deepEqual(nodeApp.imports, ['node-app-defaults'])
  assert.equal(nodeApp.path, resolve(repoRoot, 'templates/node-app/guard.json'))
})

test('app-summary emits native launcher policy JSON', () => {
  const result = spawnSync(guard, ['app-summary', '--profile', 'webex', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.profile, 'webex')
  assert.equal(summary.launcher, 'guard-webex')
  assert.equal(summary.appBundle, '/Applications/Webex.app')
  assert.equal(summary.network.mode, 'allowlist')
  assert.ok(summary.network.allowedDomains.includes('*.webex.com'))
  assert.ok(summary.filesystem.denyRead.includes('/Users'))
  assert.ok(summary.filesystem.allowRead.includes('/Applications/Webex.app'))
  assert.ok(Array.isArray(summary.findings))
})

test('install-app creates a native macOS wrapper bundle', () => {
  const targetDir = mkdtempSync(join(tmpdir(), 'guard-native-app-'))
  try {
    const result = spawnSync(
      guard,
      ['install-app', 'webex', '--dir', targetDir, '--force'],
      {
        cwd: appRoot,
        encoding: 'utf8',
      },
    )

    expectOk(result)
    const appPath = join(targetDir, 'Guard Webex.app')
    const contentsPath = join(appPath, 'Contents')
    const executablePath = join(contentsPath, 'MacOS/GuardAppLauncher')
    const configPath = join(contentsPath, 'Resources/GuardAppConfig.json')
    const iconPath = join(contentsPath, 'Resources/GuardAppIcon.icns')
    const sourceIconPath = '/Applications/Webex.app/Contents/Resources/app_publishing_logo.icns'

    assert.ok(existsSync(appPath))
    assert.ok(existsSync(join(contentsPath, 'Info.plist')))
    assert.ok(existsSync(executablePath))
    assert.ok(existsSync(configPath))
    assert.equal(existsSync(iconPath), existsSync(sourceIconPath))
    assert.match(readFileSync(join(contentsPath, 'Info.plist'), 'utf8'), /dev\.guard\.webex/)

    const config = JSON.parse(readFileSync(configPath, 'utf8'))
    assert.equal(config.profile, 'webex')
    assert.equal(config.displayName, 'Webex')
    assert.equal(config.guardPath, guard)
    assert.equal(config.bundleIdentifier, 'dev.guard.webex')
  } finally {
    rmSync(targetDir, { recursive: true, force: true })
  }
})

test('install-monitor creates a native macOS monitor bundle', () => {
  const targetDir = mkdtempSync(join(tmpdir(), 'guard-monitor-app-'))
  const stateDir = mkdtempSync(join(tmpdir(), 'guard-monitor-state-'))
  try {
    const result = spawnSync(
      guard,
      ['install-monitor', '--dir', targetDir, '--force'],
      {
        cwd: appRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          GUARD_STATE_DIR: stateDir,
        },
      },
    )

    expectOk(result)
    const appPath = join(targetDir, 'Guard Monitor.app')
    const contentsPath = join(appPath, 'Contents')
    const configPath = join(contentsPath, 'Resources/GuardAppConfig.json')

    assert.ok(existsSync(appPath))
    assert.ok(existsSync(join(contentsPath, 'Info.plist')))
    assert.ok(existsSync(join(contentsPath, 'MacOS/GuardMonitor')))
    assert.match(readFileSync(join(contentsPath, 'Info.plist'), 'utf8'), /dev\.guard\.monitor/)

    const config = JSON.parse(readFileSync(configPath, 'utf8'))
    assert.equal(config.mode, 'monitor')
    assert.equal(config.profile, 'guard')
    assert.equal(config.displayName, 'Monitor')
    assert.equal(config.guardPath, guard)
    assert.equal(config.bundleIdentifier, 'dev.guard.monitor')
    assert.equal(config.eventLogPath, join(stateDir, 'events.jsonl'))
  } finally {
    rmSync(targetDir, { recursive: true, force: true })
    rmSync(stateDir, { recursive: true, force: true })
  }
})

test('install-app all creates every native macOS wrapper bundle', () => {
  const targetDir = mkdtempSync(join(tmpdir(), 'guard-native-apps-'))
  try {
    const result = spawnSync(
      guard,
      ['install-app', 'all', '--dir', targetDir, '--force'],
      {
        cwd: appRoot,
        encoding: 'utf8',
      },
    )

    expectOk(result)
    assert.match(result.stdout, /Installed 3 Guard native apps/)
    for (const [appName, label] of [
      ['webex', 'Webex'],
      ['teams', 'Teams'],
      ['zoom', 'Zoom'],
    ]) {
      const appPath = join(targetDir, `Guard ${label}.app`)
      const configPath = join(appPath, 'Contents/Resources/GuardAppConfig.json')

      assert.ok(existsSync(appPath))
      assert.ok(existsSync(join(appPath, 'Contents/Info.plist')))
      assert.ok(existsSync(join(appPath, 'Contents/MacOS/GuardAppLauncher')))
      const config = JSON.parse(readFileSync(configPath, 'utf8'))
      assert.equal(config.profile, appName)
      assert.equal(config.displayName, label)
      assert.equal(config.guardPath, guard)
    }
  } finally {
    rmSync(targetDir, { recursive: true, force: true })
  }
})

test('list domain-presets reports denied domain presets', () => {
  const result = spawnSync(guard, ['list', 'domain-presets', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const listed = JSON.parse(result.stdout)
  assert.ok(listed.presets.telemetry.includes('*.sentry.io'))
  assert.ok(listed.presets['microsoft-telemetry'].includes('vortex.data.microsoft.com'))
})

test('profile mutations persist stable rule metadata sidecars', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-profile-metadata-'))
  const guardDir = resolve(tempRoot, '.guard')
  const profilePath = resolve(guardDir, 'guard.json')

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(profilePath, JSON.stringify({ network: {}, filesystem: {} }, null, 2) + '\n')

    const domain = spawnSync(
      guard,
      ['profile', 'add', 'network.allowedDomains', 'api.example.com', '--json'],
      {
        cwd: tempRoot,
        encoding: 'utf8',
      },
    )
    expectOk(domain)
    const domainResult = JSON.parse(domain.stdout)
    assert.equal(domainResult.changed, true)
    assert.equal(domainResult.field, 'network.allowedDomains')
    assert.equal(domainResult.value, 'api.example.com')
    assert.match(domainResult.ruleId, /^rule_[0-9a-f]{16}$/)
    assert.match(domainResult.metadataKey, /^network\.allowedDomains:[0-9a-f]{16}$/)

    let cfg = JSON.parse(readFileSync(profilePath, 'utf8'))
    assert.deepEqual(cfg.network.allowedDomains, ['api.example.com'])
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].id, domainResult.ruleId)
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].field, 'network.allowedDomains')
    assert.match(cfg.ruleMetadata[domainResult.metadataKey].valueHash, /^sha256:[0-9a-f]{64}$/)
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].source, 'cli')

    const httpRule = spawnSync(
      guard,
      [
        'profile',
        'add-http-rule',
        '--host',
        'api.openai.com',
        '--method',
        'POST',
        '--path',
        '/v1/responses',
        '--json',
      ],
      {
        cwd: tempRoot,
        encoding: 'utf8',
      },
    )
    expectOk(httpRule)
    const httpResult = JSON.parse(httpRule.stdout)
    assert.equal(httpResult.changed, true)
    assert.equal(httpResult.field, 'network.httpRules')
    assert.deepEqual(httpResult.value, {
      host: 'api.openai.com',
      methods: ['POST'],
      paths: ['/v1/responses'],
    })
    assert.match(httpResult.ruleId, /^rule_[0-9a-f]{16}$/)
    assert.match(httpResult.metadataKey, /^network\.httpRules:[0-9a-f]{16}$/)

    cfg = JSON.parse(readFileSync(profilePath, 'utf8'))
    assert.deepEqual(cfg.network.httpRules, [httpResult.value])
    assert.equal(cfg.ruleMetadata[httpResult.metadataKey].id, httpResult.ruleId)
    assert.equal(cfg.ruleMetadata[httpResult.metadataKey].field, 'network.httpRules')
    assert.match(cfg.ruleMetadata[httpResult.metadataKey].valueHash, /^sha256:[0-9a-f]{64}$/)
    assert.equal(cfg.ruleMetadata[httpResult.metadataKey].source, 'cli')

    const rawTcpRule = spawnSync(
      guard,
      [
        'profile',
        'add-raw-tcp',
        '--host',
        'localhost',
        '--resolve-at-launch',
        '--port',
        '8976',
        '--reason',
        'local OAuth callback',
        '--json',
      ],
      {
        cwd: tempRoot,
        encoding: 'utf8',
      },
    )
    expectOk(rawTcpRule)
    const rawTcpResult = JSON.parse(rawTcpRule.stdout)
    assert.equal(rawTcpResult.changed, true)
    assert.equal(rawTcpResult.field, 'network.allowedRawTcp')
    assert.deepEqual(rawTcpResult.value, {
      host: 'localhost',
      resolveAtLaunch: true,
      port: 8976,
      reason: 'local OAuth callback',
    })
    assert.match(rawTcpResult.ruleId, /^rule_[0-9a-f]{16}$/)
    assert.match(rawTcpResult.metadataKey, /^network\.allowedRawTcp:[0-9a-f]{16}$/)

    cfg = JSON.parse(readFileSync(profilePath, 'utf8'))
    assert.deepEqual(cfg.network.allowedRawTcp, [rawTcpResult.value])
    assert.equal(cfg.ruleMetadata[rawTcpResult.metadataKey].id, rawTcpResult.ruleId)
    assert.equal(cfg.ruleMetadata[rawTcpResult.metadataKey].field, 'network.allowedRawTcp')
    assert.match(cfg.ruleMetadata[rawTcpResult.metadataKey].valueHash, /^sha256:[0-9a-f]{64}$/)
    assert.equal(cfg.ruleMetadata[rawTcpResult.metadataKey].source, 'cli')

    const removeRawTcpRule = spawnSync(
      guard,
      [
        'profile',
        'remove-raw-tcp',
        '--host',
        'localhost',
        '--resolve-at-launch',
        '--port',
        '8976',
        '--reason',
        'local OAuth callback',
        '--json',
      ],
      {
        cwd: tempRoot,
        encoding: 'utf8',
      },
    )
    expectOk(removeRawTcpRule)
    const removeRawTcpResult = JSON.parse(removeRawTcpRule.stdout)
    assert.equal(removeRawTcpResult.changed, true)
    assert.deepEqual(removeRawTcpResult.after, [])

    cfg = JSON.parse(readFileSync(profilePath, 'utf8'))
    assert.deepEqual(cfg.network.allowedRawTcp, [])
    assert.equal(cfg.ruleMetadata[rawTcpResult.metadataKey], undefined)
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('settings and tls status expose explicit TLS inspection policy', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-tls-policy-'))
  const guardDir = resolve(tempRoot, '.guard')
  const profilePath = resolve(guardDir, 'guard.json')

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(profilePath, JSON.stringify({
      network: {
        backend: 'iron-proxy',
        httpRules: [{ host: 'api.example.com', methods: ['POST'], paths: ['/v1/*'] }],
      },
      filesystem: {},
    }, null, 2) + '\n')

    const initial = spawnSync(guard, ['tls', 'status', '--json'], {
      cwd: tempRoot,
      encoding: 'utf8',
    })
    expectOk(initial)
    const initialStatus = JSON.parse(initial.stdout)
    assert.equal(initialStatus.networkBackend, 'iron-proxy')
    assert.equal(initialStatus.tlsInspection.enabled, true)
    assert.equal(initialStatus.tlsInspection.explicit, false)
    assert.equal(initialStatus.tlsInspection.caScope, 'guarded-process-env')

    const disabled = spawnSync(guard, ['profile', 'tls', 'disable', '--json'], {
      cwd: tempRoot,
      encoding: 'utf8',
    })
    expectOk(disabled)
    const disabledStatus = JSON.parse(disabled.stdout)
    assert.equal(disabledStatus.changed, true)
    assert.equal(disabledStatus.after.enabled, false)
    assert.equal(disabledStatus.after.explicit, true)

    const settings = spawnSync(guard, ['settings', '--json'], {
      cwd: tempRoot,
      encoding: 'utf8',
    })
    expectOk(settings)
    const settingsJson = JSON.parse(settings.stdout)
    assert.equal(settingsJson.tlsInspection.enabled, false)
    assert.match(settingsJson.eventLogPath, /events\.jsonl$/)
    assert.equal(settingsJson.daemon.url, 'http://127.0.0.1:8765')

    const enabled = spawnSync(guard, ['profile', 'tls', 'enable', '--json'], {
      cwd: tempRoot,
      encoding: 'utf8',
    })
    expectOk(enabled)
    const enabledStatus = JSON.parse(enabled.stdout)
    assert.equal(enabledStatus.after.enabled, true)
    assert.equal(enabledStatus.after.mode, 'ephemeral-run-ca')

    const cfg = JSON.parse(readFileSync(profilePath, 'utf8'))
    assert.equal(cfg.network.tlsInspection.enabled, true)
    assert.equal(cfg.network.tlsInspection.caScope, 'guarded-process-env')
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('guardd authenticated write APIs mutate project policy and audit events', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-write-api-'))
  const guardDir = resolve(tempRoot, '.guard')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const token = 'test-token'
  let child = null

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(
      resolve(guardDir, 'guard.json'),
      JSON.stringify({ network: { allowedDomains: [] }, filesystem: {} }, null, 2) + '\n',
    )

    const ready = new Promise((resolveReady, rejectReady) => {
      child = spawn(process.execPath, [
        resolve(repoRoot, 'daemon/guardd.mjs'),
        '--port',
        '0',
        '--policy-root',
        tempRoot,
        '--event-log',
        eventLog,
        '--api-token',
        token,
        '--poll-ms',
        '100',
      ], {
        cwd: repoRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          GUARD_QUIET: '1',
        },
      })
      let stderr = ''
      const timer = setTimeout(() => rejectReady(new Error(`guardd did not start: ${stderr}`)), 5000)
      child.stderr.on('data', (chunk) => {
        stderr += chunk
        const match = stderr.match(/http:\/\/127\.0\.0\.1:(\d+)/)
        if (match) {
          clearTimeout(timer)
          resolveReady(Number(match[1]))
        }
      })
      child.on('error', rejectReady)
      child.on('exit', (code) => {
        if (!stderr.match(/http:\/\/127\.0\.0\.1:(\d+)/)) {
          clearTimeout(timer)
          rejectReady(new Error(`guardd exited before ready: ${code} ${stderr}`))
        }
      })
    })

    const port = await ready
    const base = `http://127.0.0.1:${port}`
    const unauthorized = await fetch(`${base}/profiles/guard/rules`, {
      method: 'POST',
      body: JSON.stringify({
        action: 'add',
        field: 'network.allowedDomains',
        value: 'api.example.com',
      }),
    })
    assert.equal(unauthorized.status, 401)

    const initialProfile = await fetch(`${base}/profiles/guard`, {
      headers: { authorization: `Bearer ${token}` },
    })
    assert.equal(initialProfile.status, 200)
    const initialProfileJson = await initialProfile.json()
    assert.match(initialProfileJson.version, /^sha256:[0-9a-f]{64}$/)
    assert.equal(initialProfile.headers.get('etag'), `"${initialProfileJson.version}"`)

    const staleWrite = await fetch(`${base}/profiles/guard/rules`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'if-match': 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      },
      body: JSON.stringify({
        action: 'add',
        field: 'network.allowedDomains',
        value: 'stale.example.com',
      }),
    })
    assert.equal(staleWrite.status, 412)
    const staleJson = await staleWrite.json()
    assert.equal(staleJson.error, 'version_mismatch')
    assert.equal(staleJson.currentVersion, initialProfileJson.version)

    const addDomain = await fetch(`${base}/profiles/guard/rules`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'if-match': initialProfileJson.version,
      },
      body: JSON.stringify({
        action: 'add',
        field: 'network.allowedDomains',
        value: 'api.example.com',
      }),
    })
    assert.equal(addDomain.status, 200)
    const domainResult = await addDomain.json()
    assert.equal(domainResult.changed, true)
    assert.equal(domainResult.field, 'network.allowedDomains')
    assert.match(domainResult.ruleId, /^rule_[0-9a-f]{16}$/)
    assert.match(domainResult.version, /^sha256:[0-9a-f]{64}$/)

    const addHttp = await fetch(`${base}/profiles/guard/rules`, {
      method: 'POST',
      headers: {
        'x-guard-token': token,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        action: 'add',
        field: 'network.httpRules',
        rule: { host: 'api.openai.com', methods: ['post'], paths: ['/v1/*'] },
      }),
    })
    assert.equal(addHttp.status, 200)
    const httpResult = await addHttp.json()
    assert.deepEqual(httpResult.value, {
      host: 'api.openai.com',
      methods: ['POST'],
      paths: ['/v1/*'],
    })

    const disabledDomain = await fetch(`${base}/profiles/guard/rules`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        action: 'disable',
        field: 'network.deniedDomains',
        value: 'disabled.example.com',
      }),
    })
    assert.equal(disabledDomain.status, 200)
    const disabledResult = await disabledDomain.json()
    assert.equal(disabledResult.disabled, true)
    assert.match(disabledResult.metadataKey, /^network\.deniedDomains:[0-9a-f]{16}$/)

    const tls = await fetch(`${base}/profiles/guard/tls`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ enabled: true }),
    })
    assert.equal(tls.status, 200)
    const tlsResult = await tls.json()
    assert.equal(tlsResult.after.enabled, true)

    const applyTemplate = await fetch(`${base}/templates/node-app/apply`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ profile: 'from-template', force: false }),
    })
    assert.equal(applyTemplate.status, 200)
    assert.ok(existsSync(resolve(guardDir, 'from-template.json')))

    const cfg = JSON.parse(readFileSync(resolve(guardDir, 'guard.json'), 'utf8'))
    assert.deepEqual(cfg.network.allowedDomains, ['api.example.com'])
    assert.deepEqual(cfg.network.httpRules, [httpResult.value])
    assert.equal(cfg.network.tlsInspection.enabled, true)
    assert.equal(cfg.ruleMetadata[disabledResult.metadataKey].disabled, true)
    assert.equal((cfg.network.deniedDomains ?? []).includes('disabled.example.com'), false)

    const events = await fetch(`${base}/events?type=policy.changed&limit=10`, {
      headers: { authorization: `Bearer ${token}` },
    })
    assert.equal(events.status, 200)
    const eventJson = await events.json()
    assert.ok(eventJson.events.length >= 4)
    assert.ok(eventJson.events.every((event) => event.type === 'policy.changed'))
  } finally {
    if (child) {
      child.kill('SIGTERM')
      await Promise.race([
        new Promise((resolveDone) => child.once('exit', resolveDone)),
        new Promise((resolveDone) => setTimeout(resolveDone, 1000)),
      ])
    }
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('guardd health and mutation events expose versioned API contracts', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-version-contract-'))
  const guardDir = resolve(tempRoot, '.guard')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  let daemon = null

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(
      resolve(guardDir, 'guard.json'),
      JSON.stringify({ network: { allowedDomains: [] }, filesystem: {} }, null, 2) + '\n',
    )

    daemon = await startGuarddForTest({ policyRoot: tempRoot, eventLog })
    const headers = {
      authorization: `Bearer ${daemon.token}`,
      'content-type': 'application/json',
    }

    const health = await fetch(`${daemon.base}/health`, { headers })
    assert.equal(health.status, 200)
    const healthJson = await health.json()
    assert.equal(healthJson.ok, true)
    assert.equal(healthJson.service, 'guardd')
    assert.equal(healthJson.authRequired, true)
    assert.equal(healthJson.policyRoot, tempRoot)
    assert.equal(healthJson.eventLogPath, eventLog)

    const mutation = await fetch(`${daemon.base}/profiles/guard/rules`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'add',
        field: 'network.allowedDomains',
        value: 'api.versioned.example',
      }),
    })
    assert.equal(mutation.status, 200)
    const mutationJson = await mutation.json()
    assert.equal(mutationJson.changed, true)

    const events = await fetch(`${daemon.base}/events?type=policy.changed&limit=1`, { headers })
    assert.equal(events.status, 200)
    const eventJson = await events.json()
    assert.equal(eventJson.events.length, 1)
    assert.equal(eventJson.events[0].schemaVersion, 1)
    assert.equal(eventJson.events[0].backend, 'guardd')
    assert.equal(eventJson.events[0].operation, 'add')
    assert.equal(eventJson.events[0].field, 'network.allowedDomains')
  } finally {
    await daemon?.stop()
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('guardd handles concurrent project rule writes without native app dependencies', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-concurrent-writes-'))
  const guardDir = resolve(tempRoot, '.guard')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  let daemon = null

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(
      resolve(guardDir, 'guard.json'),
      JSON.stringify({ network: { allowedDomains: [] }, filesystem: {} }, null, 2) + '\n',
    )

    daemon = await startGuarddForTest({ policyRoot: tempRoot, eventLog })
    const headers = {
      authorization: `Bearer ${daemon.token}`,
      'content-type': 'application/json',
    }
    const domains = [
      'api.concurrent-1.example',
      'api.concurrent-2.example',
      'api.concurrent-3.example',
      'api.concurrent-4.example',
      'api.concurrent-5.example',
    ]

    const responses = await Promise.all(domains.map((value) =>
      fetch(`${daemon.base}/profiles/guard/rules`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          action: 'add',
          field: 'network.allowedDomains',
          value,
        }),
      }),
    ))

    assert.deepEqual(responses.map((response) => response.status), [200, 200, 200, 200, 200])
    const results = await Promise.all(responses.map((response) => response.json()))
    assert.ok(results.every((result) => result.changed === true))
    assert.ok(results.every((result) => /^rule_[0-9a-f]{16}$/.test(result.ruleId)))

    const cfg = JSON.parse(readFileSync(resolve(guardDir, 'guard.json'), 'utf8'))
    assert.deepEqual([...cfg.network.allowedDomains].sort(), [...domains].sort())
    for (const result of results) {
      assert.equal(cfg.ruleMetadata[result.metadataKey].id, result.ruleId)
      assert.equal(cfg.ruleMetadata[result.metadataKey].source, 'guardd')
    }

    const events = await fetch(`${daemon.base}/events?type=policy.changed&limit=10`, { headers })
    assert.equal(events.status, 200)
    const eventJson = await events.json()
    assert.equal(eventJson.events.length, domains.length)
    assert.ok(eventJson.events.every((event) => event.schemaVersion === 1))
    assert.ok(eventJson.events.every((event) => event.backend === 'guardd'))
    assert.ok(eventJson.events.every((event) => event.profile === 'guard'))
    assert.ok(eventJson.events.every((event) => event.field === 'network.allowedDomains'))
    assert.ok(eventJson.events.every((event) => event.changed === true))
  } finally {
    await daemon?.stop()
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('guardd template preview reads bundled templates without mutating project profiles', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-template-preview-'))
  const guardDir = resolve(tempRoot, '.guard')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  let daemon = null

  try {
    mkdirSync(guardDir, { recursive: true })
    daemon = await startGuarddForTest({ policyRoot: tempRoot, eventLog })
    const headers = { authorization: `Bearer ${daemon.token}` }

    const templateRead = await fetch(`${daemon.base}/templates/cloudflare-wrangler`, { headers })
    assert.equal(templateRead.status, 200)
    const templateJson = await templateRead.json()
    assert.equal(templateJson.name, 'cloudflare-wrangler')
    assert.equal(templateJson.source, 'template')
    assert.equal(templateJson.path, resolve(repoRoot, 'templates/cloudflare-wrangler/guard.json'))
    assert.deepEqual(templateJson.config.imports, ['node-app-defaults', 'cloudflare-wrangler'])

    const preview = await fetch(`${daemon.base}/templates/cloudflare-wrangler/preview?profile=previewed`, { headers })
    assert.equal(preview.status, 200)
    const previewJson = await preview.json()
    assert.equal(previewJson.action, 'preview-template')
    assert.equal(previewJson.template, 'cloudflare-wrangler')
    assert.equal(previewJson.profile, 'previewed')
    assert.equal(previewJson.existing, false)
    assert.match(previewJson.templateVersion, /^sha256:[0-9a-f]{64}$/)
    assert.equal(previewJson.path, resolve(guardDir, 'previewed.json'))
    assert.equal(previewJson.effective.summary.network.allowedDomainsCount > 0, true)
    assert.equal(previewJson.effective.summary.filesystem.denyReadCount > 0, true)
    assert.equal(existsSync(resolve(guardDir, 'guard.json')), false)
    assert.equal(existsSync(resolve(guardDir, 'previewed.json')), false)

    const apply = await fetch(`${daemon.base}/templates/cloudflare-wrangler/apply`, {
      method: 'POST',
      headers: {
        ...headers,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ profile: 'guard', force: false }),
    })
    assert.equal(apply.status, 200)
    assert.ok(existsSync(resolve(guardDir, 'guard.json')))

    const collision = await fetch(`${daemon.base}/templates/cloudflare-wrangler/apply`, {
      method: 'POST',
      headers: {
        ...headers,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ profile: 'guard', force: false }),
    })
    assert.equal(collision.status, 400)
    const collisionJson = await collision.json()
    assert.equal(collisionJson.error, 'mutation_failed')
    assert.match(collisionJson.message, /project profile exists: guard/)
  } finally {
    await daemon?.stop()
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('deniedDomainPresets expand into the runtime config', () => {
  const base = networkProfileConfig()
  const profilePath = writeGuardProfile('preset-deny', {
    ...base,
    network: {
      ...base.network,
      deniedDomainPresets: ['telemetry'],
    },
  })

  try {
    const result = runGuardCommand([
      '--profile',
      'preset-deny',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.ok(cfg.network.deniedDomains.includes('*.sentry.io'))
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('profile doctor reports profile quality findings', () => {
  const result = spawnSync(guard, ['--profile', 'teams', 'profile', 'doctor', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const doctor = JSON.parse(result.stdout)
  assert.equal(doctor.profile, 'teams')
  assert.equal(doctor.status, 'warn')
  assert.ok(doctor.findings.some((finding) => finding.id === 'broad-mach-lookup'))
})

test('diff-profile compares built-in profile policy fields', () => {
  const result = spawnSync(guard, ['diff-profile', 'zoom', 'teams', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const diff = JSON.parse(result.stdout)
  assert.equal(diff.left.ref, 'zoom')
  assert.equal(diff.right.ref, 'teams')
  assert.ok(diff.changes.some((change) => change.path === 'network.allowedDomains'))
})

test('network-log summarizes guard network decision JSONL', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-network-log-'))
  const logPath = resolve(tempRoot, 'network.jsonl')
  writeFileSync(
    logPath,
    [
      JSON.stringify({ host: 'example.com', port: 443, allowed: true, reason: 'allowedDomains' }),
      JSON.stringify({ host: 'tracker.test', port: 443, allowed: false, reason: 'deniedDomains' }),
    ].join('\n') + '\n',
  )

  const result = spawnSync(guard, ['network-log', logPath], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  assert.match(result.stdout, /^Guard Network Log/m)
  assert.match(result.stdout, /example\.com:443 allowed=1 denied=0/)
  assert.match(result.stdout, /tracker\.test:443 allowed=0 denied=1/)
})

test('monitor-log summarizes persistent guard events', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-monitor-log-'))
  const logPath = resolve(tempRoot, 'events.jsonl')
  writeFileSync(
    logPath,
    [
      JSON.stringify({
        at: '2026-04-24T00:00:00.000Z',
        type: 'process.started',
        profile: 'guard',
        command: 'node server.mjs',
      }),
      JSON.stringify({
        at: '2026-04-24T00:00:01.000Z',
        type: 'network.decision',
        profile: 'guard',
        host: 'api.example.com',
        port: 443,
        allowed: true,
        reason: 'matched-rule',
      }),
    ].join('\n') + '\n',
  )

  const text = spawnSync(guard, ['monitor-log', '--limit', '2', logPath], {
    cwd: appRoot,
    encoding: 'utf8',
  })
  expectOk(text)
  assert.match(text.stdout, /^Guard Monitor Log/m)
  assert.match(text.stdout, /guard: events=2 allowed=1 denied=0/)
  assert.match(text.stdout, /network\.decision api\.example\.com:443 allow/)

  const json = spawnSync(guard, ['monitor-log', '--json', '--limit', '1', logPath], {
    cwd: appRoot,
    encoding: 'utf8',
  })
  expectOk(json)
  const summary = JSON.parse(json.stdout)
  assert.equal(summary.eventCount, 2)
  assert.equal(summary.recent.length, 1)
  assert.equal(summary.recent[0].type, 'network.decision')
})

test('discover runs with temporary discovery reporting', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-discover-'))
  const reportPath = resolve(tempRoot, 'report.md')
  const result = spawnSync(
    guard,
    [
      'discover',
      '--profile',
      'guard',
      '--report',
      reportPath,
      '--',
      'node',
      'scripts/probe.mjs',
      'env-json',
    ],
    {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_QUIET: '1',
      },
    },
  )

  expectOk(result)
  assert.equal(existsSync(reportPath), true)
  assert.match(readFileSync(reportPath, 'utf8'), /^# Guard Discovery Report/m)
})

test('GUARD_BANNER controls policy banner rendering', () => {
  const command = ['node', 'scripts/probe.mjs', 'env-json']
  const baseEnv = {
    ...process.env,
    GUARD_COLOR: 'never',
  }

  const compact = spawnSync(guard, command, {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...baseEnv,
      GUARD_BANNER: 'compact',
    },
  })
  expectOk(compact)
  assert.match(compact.stderr, /^guard ok  net none  secrets protected  run=/)
  assert.doesNotMatch(compact.stderr, /guard policy/)
  assert.doesNotMatch(compact.stderr, /✓ read/)

  const full = spawnSync(guard, command, {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...baseEnv,
      GUARD_BANNER: 'full',
    },
  })
  expectOk(full)
  assert.match(full.stderr, /guard policy/)
  assert.match(full.stderr, /✓ read/)

  const off = spawnSync(guard, command, {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...baseEnv,
      GUARD_BANNER: 'off',
    },
  })
  expectOk(off)
  assert.equal(off.stderr, '')
})

test('doctor reports the effective profile and runtime resolution', () => {
  const result = spawnSync(guard, ['doctor'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  assert.match(result.stdout, /^Guard Doctor/m)
  assert.match(result.stdout, new RegExp(`cwd: ${appRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
  assert.match(result.stdout, /effective profile source: project/)
  assert.match(result.stdout, /resolved tools:/)
  assert.match(result.stdout, /runtime node: .* \((path|fallback|override)\)/)
})

test('doctor can emit machine-readable JSON for a specific tool', () => {
  const result = spawnSync(guard, ['doctor', 'pnpm', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const info = JSON.parse(result.stdout)
  assert.equal(info.cwd, appRoot)
  assert.equal(info.profile, 'guard')
  assert.equal(info.effectiveProfileSource, 'project')
  assert.deepEqual(Object.keys(info.tools), ['pnpm'])
  assert.equal(info.tools.pnpm.status, 'resolved')
})

test('audit reports risky policy choices', () => {
  const profilePath = writeGuardProfile('audit-risk', {
    networkUnrestricted: true,
    network: {
      allowUnixSockets: ['/', '/var/run/docker.sock'],
      allowMachLookup: ['com.apple.*'],
    },
    filesystem: {
      allowRead: ['/Users', '/Volumes'],
      allowWrite: ['/Users'],
    },
  })

  try {
    const result = spawnSync(guard, ['--profile', 'audit-risk', 'audit'], {
      cwd: appRoot,
      encoding: 'utf8',
    })
    expectOk(result)
    assert.match(result.stdout, /^Guard Audit/m)
    assert.match(result.stdout, /broad-users-access/)
    assert.match(result.stdout, /volumes-access/)
    assert.match(result.stdout, /docker-socket-access/)
    assert.match(result.stdout, /network-unrestricted/)
    assert.match(result.stdout, /broad-unix-socket-access/)
    assert.match(result.stdout, /broad-mach-lookup/)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('install creates guard and shim links in the requested bin directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-install-'))
  const binDir = resolve(tempRoot, 'bin')
  const configDir = resolve(tempRoot, 'config')
  const codeRoot = resolve(tempRoot, 'managed-code')
  const escapedCodeRoot = codeRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const result = spawnSync(guard, ['install', '--bin-dir', binDir, '--code-root', codeRoot], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      GUARD_CONFIG_DIR: configDir,
    },
  })

  expectOk(result)
  assert.match(result.stdout, new RegExp(`Configured managed root: ${escapedCodeRoot}`))
  assert.equal(realpathSync(resolve(binDir, 'guard')), guard)
  assert.equal(realpathSync(resolve(binDir, 'node')), guard)
  assert.equal(realpathSync(resolve(binDir, 'pnpm')), guard)
  assert.equal(realpathSync(resolve(binDir, 'guard-zoom')), guard)
  assert.equal(realpathSync(resolve(binDir, 'guard-teams')), guard)
  assert.equal(realpathSync(resolve(binDir, 'guard-webex')), guard)
  assert.equal(
    JSON.parse(readFileSync(resolve(configDir, 'config.json'), 'utf8')).codeRoot,
    codeRoot,
  )

  const doctor = spawnSync(resolve(binDir, 'guard'), ['doctor', 'pnpm', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${binDir}:${process.env.PATH || ''}`,
      GUARD_CONFIG_DIR: configDir,
    },
  })
  expectOk(doctor)
  assert.equal(JSON.parse(doctor.stdout).codeRoot, codeRoot)

  const shimResult = spawnSync(resolve(binDir, 'node'), ['--version'], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${binDir}:${process.env.PATH || ''}`,
      GUARD_CONFIG_DIR: configDir,
      NODE_GUARD_BYPASS: '',
      GUARD_SHIM_BYPASS: '',
    },
  })
  expectOk(shimResult)
  assert.match(shimResult.stdout.trim(), /^v\d+\./)
})

test('setup configures managed root and install links non-interactively', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-setup-'))
  const binDir = resolve(tempRoot, 'bin')
  const configDir = resolve(tempRoot, 'config')
  const codeRoot = resolve(tempRoot, 'managed-code')
  const result = spawnSync(
    guard,
    ['setup', '--yes', '--bin-dir', binDir, '--code-root', codeRoot, '--no-shims'],
    {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GUARD_CONFIG_DIR: configDir,
      },
    },
  )

  expectOk(result)
  assert.match(result.stdout, /Guard setup complete/)
  assert.equal(realpathSync(resolve(binDir, 'guard')), guard)
  assert.equal(existsSync(resolve(binDir, 'node')), false)
  const config = JSON.parse(readFileSync(resolve(configDir, 'config.json'), 'utf8'))
  assert.equal(config.codeRoot, codeRoot)
  assert.equal(config.installBinDir, binDir)
  assert.equal(config.includeShims, false)
})

test('setup can be rerun after install and reports current values', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-setup-current-'))
  const binDir = resolve(tempRoot, 'bin')
  const configDir = resolve(tempRoot, 'config')
  const codeRoot = resolve(tempRoot, 'managed-code')
  const env = {
    ...process.env,
    GUARD_CONFIG_DIR: configDir,
  }

  const install = spawnSync(guard, ['install', '--bin-dir', binDir, '--code-root', codeRoot, '--force'], {
    cwd: appRoot,
    encoding: 'utf8',
    env,
  })
  expectOk(install)

  const setup = spawnSync(guard, ['setup', '--yes'], {
    cwd: appRoot,
    encoding: 'utf8',
    env,
  })

  expectOk(setup)
  assert.match(setup.stdout, /Current Guard Setup/)
  assert.match(setup.stdout, new RegExp(`managed root: ${codeRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
  assert.match(setup.stdout, new RegExp(`install dir: ${binDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
  assert.match(setup.stdout, /installed entrypoints: .*guard.*guard-zoom.*guard-teams.*guard-webex/)
  assert.match(setup.stdout, /installed shims: .*node.*pnpm.*npm.*python.*python3.*pip.*pip3/)
  assert.match(setup.stdout, /Guard setup complete/)
  assert.equal(realpathSync(resolve(binDir, 'guard')), guard)
  const config = JSON.parse(readFileSync(resolve(configDir, 'config.json'), 'utf8'))
  assert.equal(config.codeRoot, codeRoot)
  assert.equal(config.installBinDir, binDir)
  assert.equal(config.includeShims, true)
})

test('init creates a project config from the bundled template', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-init-'))
  const result = spawnSync(guard, ['init'], {
    cwd: tempRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const created = resolve(tempRoot, '.guard/guard.json')
  assert.equal(existsSync(created), true)
  const cfg = JSON.parse(readFileSync(created, 'utf8'))
  assert.deepEqual(cfg.imports, ['node-app-defaults'])
})

test('init can create the Cloudflare Wrangler template', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-init-cloudflare-'))
  const result = spawnSync(guard, ['init', 'cloudflare-wrangler'], {
    cwd: tempRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const created = resolve(tempRoot, '.guard/guard.json')
  assert.equal(existsSync(created), true)
  const cfg = JSON.parse(readFileSync(created, 'utf8'))
  assert.deepEqual(cfg.imports, ['node-app-defaults', 'cloudflare-wrangler'])
})

test('shim resolves the real tool from sanitized PATH instead of fixed package-manager paths', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-path-'))
  const fakeBin = resolve(tempRoot, 'bin')
  mkdirSync(fakeBin, { recursive: true })
  const marker = resolve(tempRoot, 'python3-marker.txt')
  const fakePython = resolve(fakeBin, 'python3')

  writeFileSync(
    fakePython,
    `#!/bin/sh\nprintf 'fake-python3\\n'\nprintf '%s\\n' "$0" > "${marker}"\n`,
    { mode: 0o755 },
  )

  const result = spawnSync(shim, ['--version'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${dirname(shim)}:${fakeBin}:${process.env.PATH || ''}`,
      GUARD_BIN: guard,
      GUARD_SHIM_TOOL: 'python3',
      GUARD_CODE_ROOT: appRoot,
      PYTHON3_GUARD_BYPASS: '1',
      GUARD_SHIM_BYPASS: '',
    },
  })

  expectOk(result)
  assert.equal(result.stdout.trim(), 'fake-python3')
  assert.equal(readFileSync(marker, 'utf8').trim(), realpathSync(fakePython))
})

test('can write files inside the allowed project root', () => {
  const outDir = resolve(appRoot, '.guard-test')
  rmSync(outDir, { recursive: true, force: true })
  expectOk(runGuard(['write-project']))
  assert.equal(existsSync(resolve(outDir, 'out.txt')), true)
})

test('cannot read the real home directory', () => {
  const realHome = process.env.HOME
  assert.ok(realHome, 'HOME must be set for this test')
  expectDenied(runGuard(['read-dir', realHome]))
})

test('cannot read /Users except explicit allowRead carve-outs', () => {
  if (!existsSync('/Users')) {
    return
  }
  expectDenied(runGuard(['read-dir', '/Users']))
})

test('cannot read the parent repo outside the project root carve-out', () => {
  expectDenied(runGuard(['read-dir', repoRoot]))
})

test('cannot write to the real home directory', () => {
  const realHome = process.env.HOME
  assert.ok(realHome, 'HOME must be set for this test')
  expectDenied(runGuard(['write-file', `${realHome}/.guard-denied-write-test`]))
})

test('cannot write to the parent repo outside the project root carve-out', () => {
  expectDenied(runGuard(['write-file', resolve(repoRoot, '.guard-denied-write-test')]))
})

test('cannot read mounted volumes when /Volumes exists', () => {
  if (!existsSync('/Volumes')) {
    return
  }
  expectDenied(runGuard(['read-dir', '/Volumes']))
})

for (const deniedPath of ['/Applications']) {
  test(`cannot read ${deniedPath}`, () => {
    if (!existsSync(deniedPath)) {
      return
    }
    expectDenied(runGuard(['read-dir', deniedPath]))
  })
}

for (const deniedPath of ['/cores', '/home']) {
  test(`cannot read ${deniedPath} when it exists`, () => {
    if (!existsSync(deniedPath)) {
      return
    }
    expectDenied(runGuard(['read-dir', deniedPath]))
  })
}

test('can use the controlled temporary directory', () => {
  expectOk(runGuard(['write-tmp']))
})

test('can bind Unix sockets inside the controlled temporary directory', () => {
  expectOk(runGuard(['unix-socket', 'tmpdir']))
})

test('cannot bind Unix sockets outside the controlled temporary directory', () => {
  expectDenied(runGuard(['unix-socket', '/tmp/guard-denied.sock']))
})

test('cannot write protected env-style files in the project', () => {
  expectDenied(runGuard(['write-file', '.env']))
})
