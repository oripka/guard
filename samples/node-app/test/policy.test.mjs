import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { connect as netConnect } from 'node:net'
import test from 'node:test'
import { connect as tlsConnect } from 'node:tls'
import { fileURLToPath } from 'node:url'

import { generateProfile } from '../../../lib/guard-manager.mjs'
import { assertLinuxBubblewrapSupported, buildBubblewrapArgs, linuxSandboxBackend } from '../../../lib/guard-bubblewrap.mjs'
import { classifySandboxDenialSensitivity, parseSandboxDenialMessage } from '../../../lib/guard-sandbox-log.mjs'
import {
  createDomainFilter,
  buildProxyEnv,
  createGuarddTlsCertificateIssuer,
  startHttpProxy,
} from '../../../lib/guard-network.mjs'

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
      GUARD_ASK_NETWORK_UI: extraEnv.GUARD_ASK_NETWORK_UI || 'tty',
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
      GUARD_ASK_NETWORK_UI: extraEnv.GUARD_ASK_NETWORK_UI || 'tty',
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
      GUARD_ASK_NETWORK_UI: extraEnv.GUARD_ASK_NETWORK_UI || 'tty',
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
        GUARD_ASK_NETWORK_UI: extraEnv.GUARD_ASK_NETWORK_UI || 'tty',
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

test('scan npm reports URL and domain literals from a project', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-npm-scan-'))
  try {
    mkdirSync(join(tempRoot, 'src'), { recursive: true })
    writeFileSync(join(tempRoot, 'package.json'), JSON.stringify({ name: 'scan-fixture' }))
    writeFileSync(
      join(tempRoot, 'src', 'client.mjs'),
      [
        'const api = "https://api.example.com/v1/responses"',
        'const docs = "docs.example.net"',
        'const email = "security@example.org"',
      ].join('\n'),
    )

    const result = spawnSync(guard, ['scan', 'npm', '--dir', tempRoot, '--json'], {
      cwd: appRoot,
      encoding: 'utf8',
      env: { ...process.env, GUARD_QUIET: '1' },
    })
    expectOk(result)
    const report = JSON.parse(result.stdout)
    assert.equal(report.type, 'npm-static-network-scan')
    assert.equal(report.packageJson, join(tempRoot, 'package.json'))
    assert.deepEqual(
      report.domains.map((item) => item.host),
      ['api.example.com', 'docs.example.net'],
    )
    assert.equal(report.domains.find((item) => item.host === 'api.example.com').urls[0], 'https://api.example.com/v1/responses')
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('scan npm skips node_modules unless requested', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-npm-scan-modules-'))
  try {
    mkdirSync(join(tempRoot, 'node_modules', 'dep'), { recursive: true })
    writeFileSync(join(tempRoot, 'package.json'), JSON.stringify({ name: 'scan-fixture' }))
    writeFileSync(join(tempRoot, 'node_modules', 'dep', 'index.js'), 'fetch("https://dep.example.com")')

    const defaultResult = spawnSync(guard, ['scan', 'npm', '--dir', tempRoot, '--json'], {
      cwd: appRoot,
      encoding: 'utf8',
      env: { ...process.env, GUARD_QUIET: '1' },
    })
    expectOk(defaultResult)
    assert.deepEqual(JSON.parse(defaultResult.stdout).domains, [])

    const includeResult = spawnSync(
      guard,
      ['scan', 'npm', '--dir', tempRoot, '--include-node-modules', '--json'],
      {
        cwd: appRoot,
        encoding: 'utf8',
        env: { ...process.env, GUARD_QUIET: '1' },
      },
    )
    expectOk(includeResult)
    assert.deepEqual(
      JSON.parse(includeResult.stdout).domains.map((item) => item.host),
      ['dep.example.com'],
    )
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

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

const ironProxyNetworkProfileConfig = ({ ask = false, httpRules = [], secretInjection = [] } = {}) => ({
  ...networkProfileConfig({ allowedDomains: [] }),
  network: {
    ...networkProfileConfig({ allowedDomains: [] }).network,
    backend: 'iron-proxy',
    ask,
    httpRules,
    secretInjection,
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

const connectSocket = (options) =>
  new Promise((resolve, reject) => {
    const socket = netConnect(options)
    socket.once('connect', () => resolve(socket))
    socket.once('error', reject)
  })

const readUntil = (socket, marker) =>
  new Promise((resolve, reject) => {
    let data = Buffer.alloc(0)
    const onData = (chunk) => {
      data = Buffer.concat([data, chunk])
      if (data.includes(marker)) {
        socket.off('data', onData)
        resolve(data)
      }
    }
    socket.on('data', onData)
    socket.once('error', reject)
    socket.once('end', () => resolve(data))
  })

const httpsThroughConnect = async ({ proxyPort, targetPort, path = '/', ca }) => {
  const socket = await connectSocket({ host: '127.0.0.1', port: proxyPort })
  socket.write(
    `CONNECT localhost:${targetPort} HTTP/1.1\r\nHost: localhost:${targetPort}\r\n\r\n`,
  )
  const connectResponse = await readUntil(socket, Buffer.from('\r\n\r\n'))
  assert.match(connectResponse.toString('utf8'), /^HTTP\/1\.[01] 200\b/)
  const tlsSocket = tlsConnect({
    socket,
    servername: 'localhost',
    ca,
    rejectUnauthorized: true,
  })
  await new Promise((resolve, reject) => {
    tlsSocket.once('secureConnect', resolve)
    tlsSocket.once('error', reject)
  })
  tlsSocket.write(
    `GET ${path} HTTP/1.1\r\nHost: localhost:${targetPort}\r\nConnection: close\r\n\r\n`,
  )
  const chunks = []
  for await (const chunk of tlsSocket) {
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

const firstExisting = (candidates) =>
  candidates.find((candidate) => candidate && existsSync(candidate)) || null

const expectNoDirectNetwork = (result) => {
  assert.notEqual(result.status, 0, 'direct network unexpectedly succeeded')
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /EPERM|ENETUNREACH|operation not permitted|permission|not permitted|denied/i,
  )
}

const startGuarddForTest = async ({ policyRoot, eventLog, token = 'test-token', extraArgs = [], extraEnv = {} }) => {
  let child = null
  const policyRootArgs = policyRoot ? ['--policy-root', policyRoot] : []
  const ready = new Promise((resolveReady, rejectReady) => {
    child = spawn(process.execPath, [
      resolve(repoRoot, 'daemon/guardd.mjs'),
      '--port',
      '0',
      ...policyRootArgs,
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
        ...extraEnv,
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

const waitForGuarddPendingAlert = async (daemon, predicate = () => true, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs
  const headers = { authorization: `Bearer ${daemon.token}` }
  while (Date.now() < deadline) {
    const response = await fetch(`${daemon.base}/alerts/pending?limit=50`, { headers })
    assert.equal(response.status, 200)
    const json = await response.json()
    const alert = json.alerts.find(predicate)
    if (alert) return alert
    await new Promise((resolveDone) => setTimeout(resolveDone, 100))
  }
  throw new Error('timed out waiting for guardd pending alert')
}

const resolveGuarddPendingAlert = async (daemon, alert, decision) => {
  const response = await fetch(`${daemon.base}/alerts/${alert.id}/resolve`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${daemon.token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(decision),
  })
  assert.equal(response.status, 200)
  return await response.json()
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

test('packaged iron-proxy is discovered next to guard bin before PATH lookup', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-packaged-iron-proxy-'))
  const packageRoot = resolve(tempRoot, 'package')
  const packageBin = resolve(packageRoot, 'bin')
  const packageLib = resolve(packageRoot, 'lib')
  mkdirSync(packageBin, { recursive: true })
  copyFileSync(guard, resolve(packageBin, 'guard'))
  chmodSync(resolve(packageBin, 'guard'), 0o755)
  writeFileSync(resolve(packageBin, 'iron-proxy'), '#!/bin/sh\nexit 0\n')
  chmodSync(resolve(packageBin, 'iron-proxy'), 0o755)
  cpSync(resolve(repoRoot, 'lib'), packageLib, { recursive: true })

  const result = spawnSync(resolve(packageBin, 'guard'), ['doctor', 'node', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      GUARD_QUIET: '1',
      GUARD_SHIM_BYPASS: '1',
      GUARD_IRON_PROXY_BIN: '',
      PATH: `/usr/bin:/bin`,
    },
  })

  expectOk(result)
  const report = JSON.parse(result.stdout)
  assert.equal(realpathSync(report.ironProxy.command), realpathSync(resolve(packageBin, 'iron-proxy')))
})

test('linux bubblewrap backend denies network when policy has no egress exceptions', { skip: process.platform !== 'linux' }, () => {
  const args = buildBubblewrapArgs({
    cfg: networkProfileConfig({ allowedDomains: [] }),
    commandArgs: ['/usr/bin/true'],
    env: ['HOME=/tmp/guard-home', 'PATH=/usr/bin:/bin'],
    cwd: appRoot,
  })

  assert.ok(args.includes('--unshare-net'))
  assert.deepEqual(args.slice(-2), ['/usr/bin/env', '/usr/bin/true'])
})

test('linux bubblewrap backend enables isolated loopback for local listeners', { skip: process.platform !== 'linux' }, () => {
  const cfg = networkProfileConfig({ allowedDomains: [] })
  cfg.network.allowLocalBinding = true
  cfg.network.allowLoopbackPorts = [3000]

  assert.equal(linuxSandboxBackend({ network: cfg.network }), 'bubblewrap-loopback-network')
  assert.equal(assertLinuxBubblewrapSupported(cfg), 'bubblewrap-loopback-network')

  const args = buildBubblewrapArgs({
    cfg,
    commandArgs: ['/usr/bin/true'],
    env: ['HOME=/tmp/guard-home', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin'],
    cwd: appRoot,
  })

  assert.ok(args.includes('--unshare-net'))
  assert.ok(args.includes('guard-bwrap-loopback'))
  assert.match(args.join('\n'), /ip link set lo up/)
  assert.deepEqual(args.slice(-2), ['/usr/bin/env', '/usr/bin/true'])
})

test('linux bubblewrap backend fails closed for proxy-routed domain policy', { skip: process.platform !== 'linux' }, () => {
  assert.throws(
    () => assertLinuxBubblewrapSupported(networkProfileConfig({ allowedDomains: ['example.com'] }), { proxyEnabled: true }),
    /does not yet support Guard proxy\/domain\/httpRules enforcement/,
  )
})

test('supply-chain install hardening denies package persistence writes and risky children', () => {
  const profile = generateProfile(
    {
      supplyChain: {
        installHardening: true,
      },
      network: {},
      filesystem: {
        allowWrite: ['${GUARD_PROJECT_DIR}', '${GUARD_RUN_DIR}'],
      },
    },
    {
      cwd: appRoot,
      projectDir: appRoot,
      guardRunDir: join(appRoot, '.guard-run-test'),
    },
  )

  assert.match(profile, /\(deny process-exec[\s\S]*\(literal "\/bin\/zsh"\)/)
  assert.match(profile, /\(deny process-exec[\s\S]*\(literal "\/usr\/bin\/curl"\)/)
  assert.match(profile, /\(deny process-exec[\s\S]*\(literal "\/usr\/bin\/gh"\)/)
  assert.match(profile, /\(deny file-write\*[\s\S]*\.github\/workflows/)
  assert.match(profile, /\(deny file-write\*[\s\S]*site-packages\/[^"]*\.pth/)
  assert.match(profile, /\(deny file-write\*[\s\S]*\.zshrc/)
})

test('buildProxyEnv exposes reusable SOCKS and SSH proxy environment', () => {
  const env = buildProxyEnv({ httpPort: 18080, socksPort: 19090 })

  assert.ok(env.includes('GUARD_SOCKS_PROXY=localhost:19090'))
  assert.ok(env.includes('GUARD_SSH_PROXY_COMMAND=nc -X 5 -x localhost:19090 %h %p'))
  assert.ok(env.includes("GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x localhost:19090 %h %p'"))
})

test('version probes keep filesystem sandbox while skipping loopback port network rules', () => {
  const profilePath = writeGuardProfile('version-probe-loopback-ports', {
    ...networkProfileConfig({
      allowedDomains: ['example.com'],
    }),
    network: {
      ...networkProfileConfig({ allowedDomains: ['example.com'] }).network,
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
        ['--profile', 'version-probe-loopback-ports', ...command],
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

test('process.allowedExecutables emits a process exec allowlist', () => {
  const profile = generateProfile(
    {
      process: {
        allowedExecutables: ['/bin/echo', '/opt/homebrew/bin/node*'],
      },
      network: {},
    },
    { cwd: appRoot },
  )

  assert.match(profile, /\(allow process-exec[\s\S]*\(literal "\/usr\/bin\/env"\)/)
  assert.match(profile, /\(allow process-exec[\s\S]*\(literal "\/bin\/echo"\)/)
  assert.ok(profile.includes('(regex "^/opt/homebrew/bin/node[^/]*$")'))
  assert.doesNotMatch(profile, /\(allow process-exec\)\n/)
})

test('process.allowedExecutables is enforced by sandbox-exec', { skip: process.platform !== 'darwin' || !existsSync('/usr/bin/sandbox-exec') }, () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-process-policy-'))
  const profilePath = join(tempRoot, 'profile.sb')
  try {
    const profile = generateProfile(
      {
        process: {
          allowedExecutables: ['/bin/echo'],
        },
        network: {},
      },
      { cwd: appRoot },
    )
    writeFileSync(profilePath, profile)

    const allowed = spawnSync('/usr/bin/sandbox-exec', ['-f', profilePath, '/bin/echo', 'ok'], {
      encoding: 'utf8',
    })
    expectOk(allowed)
    assert.equal(allowed.stdout, 'ok\n')

    const denied = spawnSync('/usr/bin/sandbox-exec', ['-f', profilePath, '/bin/ls'], {
      encoding: 'utf8',
    })
    assert.notEqual(denied.status, 0)
    assert.match(denied.stderr, /Operation not permitted|permission denied/i)
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
  }
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

test('guard defaults guarded runs to the iron-proxy ask-and-learn backend', () => {
  const profilePath = writeGuardProfile(
    'default-deep-egress',
    networkProfileConfig({ allowedDomains: [] }),
  )

  try {
    const result = runGuardCommand([
      '--profile',
      'default-deep-egress',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.network.backend, 'iron-proxy')
    assert.equal(cfg.network.ask, true)
    assert.equal(cfg.network.learnHttpRules, true)
    assert.equal(cfg.network.upgradeDomainAllows, true)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('profiles can opt out of default network ask learning', () => {
  const profilePath = writeGuardProfile(
    'default-deep-egress-opt-out',
    {
      ...networkProfileConfig({ allowedDomains: [] }),
      network: {
        ...networkProfileConfig({ allowedDomains: [] }).network,
        ask: false,
        learnHttpRules: false,
        upgradeDomainAllows: false,
      },
    },
  )

  try {
    const result = runGuardCommand([
      '--profile',
      'default-deep-egress-opt-out',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.network.backend, 'iron-proxy')
    assert.equal(cfg.network.ask, false)
    assert.equal(cfg.network.learnHttpRules, false)
    assert.equal(cfg.network.upgradeDomainAllows, false)
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('default network ask delegates to managed guardd for native popups when available', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-native-ask-connection-'))
  const profilePath = writeGuardProfile(
    'default-native-ask',
    networkProfileConfig({ allowedDomains: [] }),
  )
  mkdirSync(tempRoot, { recursive: true })
  writeFileSync(
    join(tempRoot, 'guardd-connection.json'),
    JSON.stringify({ url: 'http://127.0.0.1:18797', token: 'test-token' }, null, 2),
  )

  try {
    const result = runGuardCommand([
      '--profile',
      'default-native-ask',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ], {
      GUARD_STATE_DIR: tempRoot,
      GUARD_ASK_NETWORK_UI: 'native',
    })
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.network.ask, true)
    assert.equal(cfg.network.decisionMode, 'guardd')
    assert.equal(cfg.network.nativePromptFallback, true)
  } finally {
    rmSync(profilePath, { force: true })
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('--deep-egress remains a compatibility flag for the iron-proxy backend', () => {
  const profilePath = writeGuardProfile(
    'deep-egress-flag',
    networkProfileConfig({ allowedDomains: [] }),
  )

  try {
    const result = runGuardCommand([
      '--deep-egress',
      '--profile',
      'deep-egress-flag',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.network.backend, 'iron-proxy')
  } finally {
    rmSync(profilePath, { force: true })
  }
})

test('--daemon-policy opts a run into guardd-backed network decisions', () => {
  const profilePath = writeGuardProfile(
    'daemon-policy-flag',
    networkProfileConfig({ allowedDomains: [] }),
  )

  try {
    const result = runGuardCommand([
      '--daemon-policy',
      '--profile',
      'daemon-policy-flag',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(result)
    const cfg = JSON.parse(result.stdout)
    assert.equal(cfg.network.ask, true)
    assert.equal(cfg.network.decisionMode, 'guardd')

    const localAsk = runGuardCommand([
      '--ask-network',
      '--profile',
      'daemon-policy-flag',
      'node',
      'scripts/probe.mjs',
      'runtime-config-json',
    ])
    expectOk(localAsk)
    const localCfg = JSON.parse(localAsk.stdout)
    assert.equal(localCfg.network.ask, true)
    assert.equal(localCfg.network.decisionMode, undefined)
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

test('iron-proxy backend swaps proxy tokens for scoped secrets without exposing the real secret to the workload', async () => {
  const profilePath = writeGuardProfile(
    'network-iron-secret-injection',
    ironProxyNetworkProfileConfig({
      httpRules: [
        {
          host: 'localhost',
          methods: ['GET'],
          paths: ['/secret', '/blocked'],
        },
      ],
      secretInjection: [
        {
          name: 'OPENAI_API_KEY',
          source: { type: 'env', var: 'GUARD_TEST_REAL_SECRET' },
          proxyValue: 'guard-proxy-token-for-test',
          matchHeaders: ['Authorization'],
          require: true,
          rules: [
            {
              host: 'localhost',
              methods: ['GET'],
              paths: ['/secret'],
            },
          ],
        },
      ],
    }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      authorization: req.headers.authorization || '',
    }))
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-secret-injection',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      '-H',
      'Authorization: Bearer guard-proxy-token-for-test',
      `http://localhost:${port}/secret`,
    ], {
      GUARD_TEST_REAL_SECRET: 'real-secret-value-from-parent-only',
    })
    expectOk(result)
    const json = JSON.parse(result.stdout)
    assert.equal(json.authorization, 'Bearer real-secret-value-from-parent-only')
    assert.equal(result.stdout.includes('guard-proxy-token-for-test'), false)

    const missingProxyToken = await runGuardCommandAsync([
      '--profile',
      'network-iron-secret-injection',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      '-H',
      'Authorization: Bearer user-bypassed-token',
      `http://localhost:${port}/secret`,
    ], {
      GUARD_TEST_REAL_SECRET: 'real-secret-value-from-parent-only',
    })
    assert.notEqual(missingProxyToken.status, 0)
    assert.match(`${missingProxyToken.stderr}\n${missingProxyToken.stdout}`, /403|Forbidden/i)

    const wrongPath = await runGuardCommandAsync([
      '--profile',
      'network-iron-secret-injection',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      '-H',
      'Authorization: Bearer guard-proxy-token-for-test',
      `http://localhost:${port}/blocked`,
    ], {
      GUARD_TEST_REAL_SECRET: 'real-secret-value-from-parent-only',
    })
    expectOk(wrongPath)
    const wrongPathJson = JSON.parse(wrongPath.stdout)
    assert.equal(wrongPathJson.authorization, 'Bearer guard-proxy-token-for-test')
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

test('iron-proxy default ask allows existing domain rules non-interactively and suggests path upgrade', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-iron-upgrade-domain-'))
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const profilePath = writeGuardProfile(
    'network-iron-upgrade-domain',
    {
      ...ironProxyNetworkProfileConfig({ ask: true }),
      network: {
        ...ironProxyNetworkProfileConfig({ ask: true }).network,
        allowedDomains: ['localhost'],
      },
    },
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`domain-ok ${req.url}\n`)
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-upgrade-domain',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/v1/responses`,
    ], {
      GUARD_EVENT_LOG: eventLog,
    })
    expectOk(result)
    assert.match(result.stdout, /domain-ok/)
    const events = readFileSync(eventLog, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
    assert.ok(events.some((event) =>
      event.type === 'network.decision' &&
        event.reason === 'domain-allow-upgrade-skipped-noninteractive' &&
        event.suggestedRule?.paths?.includes('/v1/*'),
    ))
    const cfg = JSON.parse(readFileSync(profilePath, 'utf8'))
    assert.deepEqual(cfg.network.httpRules || [], [])
  } finally {
    rmSync(profilePath, { force: true })
    rmSync(tempRoot, { recursive: true, force: true })
    await closeServer(server)
  }
})

test('--deep-egress --daemon-policy routes iron-proxy decisions through guardd alerts', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-iron-daemon-policy-'))
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const profilePath = writeGuardProfile(
    'network-iron-daemon-policy',
    ironProxyNetworkProfileConfig({ ask: false }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`iron-daemon-ok ${req.method} ${req.url}\n`)
  })
  const port = await listenLoopback(server)
  let daemon = null

  try {
    daemon = await startGuarddForTest({
      policyRoot: appRoot,
      eventLog,
      extraEnv: { GUARD_STATE_DIR: resolve(tempRoot, 'state') },
    })
    const run = runGuardCommandAsync([
      '--deep-egress',
      '--daemon-policy',
      '--profile',
      'network-iron-daemon-policy',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/guardd-path`,
    ], {
      GUARD_DAEMON_URL: daemon.base,
      GUARD_DAEMON_TOKEN: daemon.token,
      GUARD_DAEMON_DECISION_TIMEOUT_MS: '10000',
    })

    const alert = await waitForGuarddPendingAlert(
      daemon,
      (candidate) => candidate.host === 'localhost' && candidate.reason === 'daemon-http-policy',
      10000,
    )
    assert.equal(alert.method, 'GET')
    assert.equal(alert.path, '/guardd-path')
    await resolveGuarddPendingAlert(daemon, alert, { action: 'allow', duration: 'session' })

    const result = await run
    expectOk(result)
    assert.equal(result.stdout, 'iron-daemon-ok GET /guardd-path\n')
  } finally {
    await daemon?.stop()
    rmSync(profilePath, { force: true })
    rmSync(tempRoot, { recursive: true, force: true })
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

test('network ask filter caches decisions by host and port for the run', async () => {
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
  assert.equal(await filter('localhost', 8080), true)
  assert.equal(await filter('localhost', 9090), true)
  assert.deepEqual(prompts, [
    { host: 'localhost', port: 8080 },
    { host: 'localhost', port: 9090 },
  ])
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

test('--daemon-policy sends normal proxy decisions through guardd pending alerts', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-daemon-policy-'))
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const profilePath = writeGuardProfile(
    'network-daemon-policy',
    {
      ...networkProfileConfig({ allowedDomains: [] }),
      network: {
        ...networkProfileConfig({ allowedDomains: [] }).network,
        backend: 'guard',
      },
    },
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`daemon-policy-ok ${req.url}\n`)
  })
  const port = await listenLoopback(server)
  let daemon = null

  try {
    daemon = await startGuarddForTest({
      policyRoot: appRoot,
      eventLog,
      extraEnv: { GUARD_STATE_DIR: resolve(tempRoot, 'state') },
    })
    const run = runGuardCommandAsync([
      '--daemon-policy',
      '--profile',
      'network-daemon-policy',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/allowed-by-daemon`,
    ], {
      GUARD_DAEMON_URL: daemon.base,
      GUARD_DAEMON_TOKEN: daemon.token,
      GUARD_DAEMON_DECISION_TIMEOUT_MS: '10000',
    })

    const alert = await waitForGuarddPendingAlert(
      daemon,
      (candidate) => candidate.host === 'localhost' && candidate.reason === 'daemon-network-policy',
    )
    assert.equal(alert.command.includes('/usr/bin/curl'), true)
    await resolveGuarddPendingAlert(daemon, alert, { action: 'allow', duration: 'session' })

    const result = await run
    expectOk(result)
    assert.equal(result.stdout, 'daemon-policy-ok /allowed-by-daemon\n')
  } finally {
    await daemon?.stop()
    rmSync(profilePath, { force: true })
    rmSync(tempRoot, { recursive: true, force: true })
    await closeServer(server)
  }
})

test('--daemon-policy fails closed when guardd is unavailable', async () => {
  const profilePath = writeGuardProfile(
    'network-daemon-policy-unavailable',
    networkProfileConfig({ allowedDomains: [] }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-pass\n')
  })
  const port = await listenLoopback(server)

  try {
    const result = await runGuardCommandAsync([
      '--daemon-policy',
      '--profile',
      'network-daemon-policy-unavailable',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/`,
    ], {
      GUARD_DAEMON_URL: 'http://127.0.0.1:9',
      GUARD_DAEMON_TOKEN: 'test-token',
      GUARD_DAEMON_DECISION_TIMEOUT_MS: '1000',
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /guardd policy unavailable/)
    assert.match(`${result.stderr}\n${result.stdout}`, /403|blocked/i)
  } finally {
    rmSync(profilePath, { force: true })
    await closeServer(server)
  }
})

test('HTTPS CONNECT tunnels are filtered by allowedDomains', async () => {
  const cfg = networkProfileConfig()
  cfg.network.backend = 'guard'
  const profilePath = writeGuardProfile('network-connect', cfg)
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

test('CONNECT TLS interception uses guardd host certs and filters decrypted HTTPS paths', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-connect-tls-'))
  const eventLog = join(tempRoot, 'events.jsonl')
  const stateDir = join(tempRoot, 'state')
  const daemon = await startGuarddForTest({
    policyRoot: tempRoot,
    eventLog,
    token: 'tls-test-token',
    extraEnv: { GUARD_STATE_DIR: stateDir },
  })
  const headers = {
    authorization: `Bearer ${daemon.token}`,
    'content-type': 'application/json',
  }
  let upstream = null
  let proxy = null

  try {
    const caResponse = await fetch(`${daemon.base}/tls/ca`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'generate', days: 1, commonName: 'Guard Test CA' }),
    })
    assert.equal(caResponse.status, 200)
    const caJson = await caResponse.json()
    const ca = readFileSync(caJson.paths.certificatePath, 'utf8')
    const issuer = createGuarddTlsCertificateIssuer({
      baseUrl: daemon.base,
      token: daemon.token,
      days: 1,
    })
    const issued = await issuer.issue('localhost')

    upstream = createHttpsServer(
      { cert: issued.cert, key: issued.key },
      (req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end(`tls-ok ${req.method} ${req.url}\n`)
      },
    )
    const upstreamPort = await listenLoopback(upstream)
    const seen = []
    proxy = await startHttpProxy({
      filter: async (host, port) => host === 'localhost' && port === upstreamPort,
      tlsIntercept: true,
      tlsCertificateIssuer: issuer,
      upstreamTls: { ca },
      requestFilter: async (request) => {
        seen.push(`${request.method} ${request.host}${request.path}`)
        return request.path === '/allowed'
      },
    })

    const allowed = await httpsThroughConnect({
      proxyPort: proxy.port,
      targetPort: upstreamPort,
      path: '/allowed',
      ca,
    })
    assert.match(allowed, /200 OK/)
    assert.match(allowed, /tls-ok GET \/allowed/)

    const blocked = await httpsThroughConnect({
      proxyPort: proxy.port,
      targetPort: upstreamPort,
      path: '/blocked',
      ca,
    })
    assert.match(blocked, /403 Forbidden/)
    assert.deepEqual(seen, [
      'GET localhost/allowed',
      'GET localhost/blocked',
    ])
  } finally {
    if (proxy) await proxy.close()
    if (upstream) await closeServer(upstream)
    await daemon.stop()
    rmSync(tempRoot, { recursive: true, force: true })
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

test('WebSocket proxy upstream failures return a proxy error', async () => {
  const closedServer = createHttpServer()
  const closedPort = await listenLoopback(closedServer)
  await closeServer(closedServer)

  const proxy = await startHttpProxy({
    filter: async () => true,
  })
  const socket = await connectSocket({ host: '127.0.0.1', port: proxy.port })

  try {
    socket.write(
      [
        `GET ws://localhost:${closedPort}/socket HTTP/1.1`,
        `Host: localhost:${closedPort}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        '',
        '',
      ].join('\r\n'),
    )
    const response = await readUntil(socket, Buffer.from('\r\n\r\n'))
    assert.match(response.toString('utf8'), /^HTTP\/1\.[01] 502 Upstream Unavailable\b/)
  } finally {
    socket.destroy()
    await proxy.close()
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

test('iron-proxy backend reuses guardd local TLS CA and warms host certificate cache', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-iron-guardd-ca-'))
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const stateDir = resolve(tempRoot, 'state')
  const profilePath = writeGuardProfile(
    'network-iron-guardd-ca',
    ironProxyNetworkProfileConfig({
      httpRules: [{ host: 'localhost', methods: ['GET'], paths: ['/warm'] }],
    }),
  )
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`guardd-ca-ok ${req.url}\n`)
  })
  const port = await listenLoopback(server)
  let daemon = null

  try {
    daemon = await startGuarddForTest({
      policyRoot: appRoot,
      eventLog,
      extraEnv: { GUARD_STATE_DIR: stateDir },
    })
    const result = await runGuardCommandAsync([
      '--profile',
      'network-iron-guardd-ca',
      '/usr/bin/curl',
      '--noproxy',
      '',
      '-fsS',
      `http://localhost:${port}/warm`,
    ], {
      GUARD_EVENT_LOG: eventLog,
      GUARD_DAEMON_URL: daemon.base,
      GUARDD_API_TOKEN: daemon.token,
    })
    expectOk(result)

    const events = readFileSync(eventLog, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line))
    const warmed = events.find((event) => event.type === 'tls.cert_cache_warmed')
    assert.equal(warmed.backend, 'iron-proxy')
    assert.equal(warmed.globalTrustManaged, false)
    assert.equal(warmed.warmed.some((entry) => entry.host === 'localhost'), true)
    const flow = events.find((event) =>
      event.type === 'network.flow' &&
      event.backend === 'iron-proxy' &&
      String(event.host || '').startsWith('localhost') &&
      event.path === '/warm')
    assert.equal(flow?.transport, 'iron-proxy')
    assert.equal(flow?.status, 'allowed')
    assert.equal(flow?.statusCode, 200)
  } finally {
    rmSync(profilePath, { force: true })
    rmSync(tempRoot, { recursive: true, force: true })
    await closeServer(server)
    await daemon?.stop()
  }
})

test('guardd regenerates TLS CA when existing CA fails validity check', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-expired-ca-'))
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const stateDir = resolve(tempRoot, 'state')
  const opensslWrapper = resolve(tempRoot, 'openssl-expired-ca.sh')
  writeFileSync(opensslWrapper, `#!/bin/sh
has_checkend=0
has_guard_ca=0
for arg in "$@"; do
  [ "$arg" = "-checkend" ] && has_checkend=1
  case "$arg" in
    *guard-local-ca.pem) has_guard_ca=1 ;;
  esac
done
[ "$has_checkend" = "1" ] && [ "$has_guard_ca" = "1" ] && exit 1
exec /usr/bin/openssl "$@"
`)
  chmodSync(opensslWrapper, 0o755)
  let daemon = null

  try {
    daemon = await startGuarddForTest({
      policyRoot: appRoot,
      eventLog,
      extraEnv: {
        GUARD_STATE_DIR: stateDir,
        GUARDD_OPENSSL: opensslWrapper,
      },
    })
    const headers = {
      authorization: `Bearer ${daemon.token}`,
      'content-type': 'application/json',
    }
    const first = await fetch(`${daemon.base}/tls/ca`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'generate', days: 30, commonName: 'Guard Test CA' }),
    })
    assert.equal(first.status, 200)
    const firstJson = await first.json()
    assert.equal(firstJson.changed, true)
    assert.equal(firstJson.lifecycle, 'active')

    const regenerated = await fetch(`${daemon.base}/tls/ca`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'generate', days: 30, commonName: 'Guard Test CA' }),
    })
    assert.equal(regenerated.status, 200)
    const regeneratedJson = await regenerated.json()
    assert.equal(regeneratedJson.changed, true)
    assert.equal(regeneratedJson.lifecycle, 'active')
    assert.notEqual(regeneratedJson.serial, firstJson.serial)
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
    await daemon?.stop()
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
  assert.match(result.stdout, /guard off <command> \[args\.\.\.\]/)
  assert.match(result.stdout, /guard unprotected <command> \[args\.\.\.\]/)
  assert.match(result.stdout, /guard install-apps \[--dir DIR\] \[--force\]/)
  assert.match(result.stdout, /guard monitor-log \[--json\] \[--limit N\] \[PATH\]/)
  assert.match(result.stdout, /guard install-monitor \[--dir DIR\] \[--force\]/)
})

test('guard off runs command without guard runtime', () => {
  const result = spawnSync(guard, ['off', process.execPath, '-e', 'process.stdout.write(process.env.GUARD_ACTIVE || "unset")'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  assert.equal(result.stdout, 'unset')
})

test('guard unprotected runs command without guard runtime', () => {
  const result = spawnSync(guard, ['unprotected', process.execPath, '-e', 'process.stdout.write(process.env.GUARD_ACTIVE || "unset")'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  assert.equal(result.stdout, 'unset')
})

test('list profile can emit machine-readable JSON', () => {
  const result = spawnSync(guard, ['list', 'profile', '--json'], {
    cwd: appRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const listed = JSON.parse(result.stdout)
  const names = listed.profiles.map((profile) => profile.name)
  assert.deepEqual(names, ['guard', 'teams', 'webex', 'zoom-discovery', 'zoom'])
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
    assert.match(result.stdout, /Installed 4 Guard native apps/)
    for (const [appName, label] of [
      ['webex', 'Webex'],
      ['teams', 'Teams'],
      ['zoom', 'Zoom'],
      ['zoom-discovery', 'Zoom Discovery'],
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
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].layer, 'destination')
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].action, 'allow')
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].lifetime, 'persistent')
    assert.equal(cfg.ruleMetadata[domainResult.metadataKey].approvalState, 'approved')

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
    assert.equal(cfg.ruleMetadata[httpResult.metadataKey].layer, 'http')
    assert.match(cfg.ruleMetadata[httpResult.metadataKey].scope, /POST api\.openai\.com/)

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
    assert.equal(cfg.ruleMetadata[rawTcpResult.metadataKey].layer, 'raw-tcp')

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
    assert.equal(healthJson.apiVersion, 1)
    assert.equal(healthJson.authRequired, true)
    assert.equal(healthJson.policyRoot, tempRoot)
    assert.equal(healthJson.eventLogPath, eventLog)
    assert.equal(healthJson.stateDir, join(process.env.HOME, 'Library', 'Application Support', 'guard'))
    assert.equal(healthJson.paths.eventLogPath, eventLog)
    assert.equal(healthJson.auth.mutationTokenRequired, true)

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

test('guardd defaults to global app-support profile storage without a project root', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-global-policy-'))
  const stateDir = resolve(tempRoot, 'state')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  let daemon = null

  try {
    daemon = await startGuarddForTest({
      eventLog,
      extraEnv: {
        GUARD_STATE_DIR: stateDir,
        GUARD_PROJECT_DIR: '',
        GUARDD_POLICY_ROOT: '',
      },
    })
    const headers = {
      authorization: `Bearer ${daemon.token}`,
      'content-type': 'application/json',
    }

    const health = await fetch(`${daemon.base}/health`, { headers })
    assert.equal(health.status, 200)
    const healthJson = await health.json()
    assert.equal(healthJson.policyRoot, stateDir)
    assert.equal(healthJson.paths.projectProfilesDir, resolve(stateDir, '.guard'))

    const mutation = await fetch(`${daemon.base}/profiles/guard/rules`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'add',
        field: 'network.allowedDomains',
        value: 'global-config.example',
      }),
    })
    assert.equal(mutation.status, 200)
    const mutationJson = await mutation.json()
    assert.equal(mutationJson.changed, true)
    assert.equal(mutationJson.path, resolve(stateDir, '.guard/guard.json'))

    const globalProfile = JSON.parse(readFileSync(resolve(stateDir, '.guard/guard.json'), 'utf8'))
    assert.deepEqual(globalProfile.network.allowedDomains, ['global-config.example'])
    assert.equal(globalProfile.metadata.source, 'guardd-global-config')
  } finally {
    await daemon?.stop()
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('guardd state, TLS CA scaffold, and bounded event log truncation stay local', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-state-hardening-'))
  const guardDir = resolve(tempRoot, '.guard')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const stateDir = resolve(tempRoot, 'state')
  let daemon = null

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(
      resolve(guardDir, 'guard.json'),
      JSON.stringify({ network: { allowedDomains: [] }, filesystem: {} }, null, 2) + '\n',
    )
    writeFileSync(
      eventLog,
      [
        JSON.stringify({ schemaVersion: 1, type: 'seed', n: 1 }),
        '{not-json',
        JSON.stringify({ schemaVersion: 99, type: 'seed', n: 99 }),
        JSON.stringify({ schemaVersion: 1, type: 'seed', n: 2 }),
        JSON.stringify({ schemaVersion: 1, type: 'seed', n: 3 }),
      ].join('\n') + '\n',
    )

    daemon = await startGuarddForTest({
      policyRoot: tempRoot,
      eventLog,
      extraEnv: { GUARD_STATE_DIR: stateDir },
    })
    const headers = {
      authorization: `Bearer ${daemon.token}`,
      'content-type': 'application/json',
    }

    const state = await fetch(`${daemon.base}/state`, { headers })
    assert.equal(state.status, 200)
    const stateJson = await state.json()
    assert.equal(stateJson.service, 'guardd')
    assert.equal(stateJson.paths.policyRoot, tempRoot)
    assert.equal(stateJson.paths.eventLogPath, eventLog)
    assert.equal(stateJson.paths.stateDir, stateDir)
    assert.equal(stateJson.tail.eventLogSize > 0, true)
    assert.equal(stateJson.tail.metadataPath, resolve(stateDir, 'daemon-state.json'))
    assert.equal(stateJson.tail.recovery.attempted, true)
    assert.equal(stateJson.tail.retention.maxEvents > 0, true)
    assert.equal(stateJson.tail.invalidLineCount, 1)
    assert.equal(stateJson.tail.tamperLineCount, 1)
    assert.equal(stateJson.tail.index.schemaVersion, 2)
    assert.equal(stateJson.tail.index.rebuild.completed, true)
    assert.equal(stateJson.tail.index.rebuild.invalidLineCount, 1)
    assert.equal(stateJson.tail.index.rebuild.tamperLineCount, 1)
    assert.equal(stateJson.auth.token.configured, true)
    assert.match(stateJson.auth.token.fingerprint, /^sha256:[0-9a-f]{16}$/)
    assert.equal(stateJson.auth.token.secretExposed, false)

    const tokenStatus = await fetch(`${daemon.base}/auth/token`, { headers })
    assert.equal(tokenStatus.status, 200)
    const tokenStatusJson = await tokenStatus.json()
    assert.equal(tokenStatusJson.storage, 'runtime-memory')
    assert.equal(tokenStatusJson.length, daemon.token.length)
    assert.match(tokenStatusJson.fingerprint, /^sha256:[0-9a-f]{16}$/)
    assert.equal(Object.hasOwn(tokenStatusJson, 'token'), false)
    assert.equal(tokenStatusJson.keychainDescriptor.invokedByGuardd, false)

    const rotatedRuntimeToken = 'rotated-test-token-for-guardd-runtime-123'
    const rotateToken = await fetch(`${daemon.base}/auth/token/rotate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ newToken: rotatedRuntimeToken }),
    })
    assert.equal(rotateToken.status, 200)
    const rotateTokenJson = await rotateToken.json()
    assert.equal(rotateTokenJson.action, 'rotate-runtime-token')
    assert.equal(rotateTokenJson.changed, true)
    assert.equal(rotateTokenJson.token, rotatedRuntimeToken)
    assert.notEqual(rotateTokenJson.auth.fingerprint, tokenStatusJson.fingerprint)
    assert.equal(rotateTokenJson.auth.rotation.persistsAcrossRestart, false)

    const oldTokenRejected = await fetch(`${daemon.base}/auth/token`, {
      headers: { authorization: `Bearer ${daemon.token}` },
    })
    assert.equal(oldTokenRejected.status, 401)
    headers.authorization = `Bearer ${rotatedRuntimeToken}`

    const tlsCa = await fetch(`${daemon.base}/tls/ca`, { headers })
    assert.equal(tlsCa.status, 200)
    const tlsCaJson = await tlsCa.json()
    assert.equal(tlsCaJson.scaffold, false)
    assert.equal(tlsCaJson.installedGlobally, false)
    assert.equal(tlsCaJson.globalTrustManaged, false)
    assert.equal(tlsCaJson.trustStoreAction, 'not-managed-by-guardd')
    assert.match(tlsCaJson.paths.certificatePath, /guard-local-ca\.pem$/)
    assert.equal(tlsCaJson.generated.certificate, false)
    assert.equal(tlsCaJson.privateKeyProtection.storage, 'filesystem')
    assert.equal(tlsCaJson.privateKeyProtection.secretExposed, false)
    assert.equal(tlsCaJson.privateKeyProtection.keychainDescriptor.invokedByGuardd, false)

    const generateCa = await fetch(`${daemon.base}/tls/ca`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'generate', days: 1, commonName: 'Guard Test CA' }),
    })
    assert.equal(generateCa.status, 200)
    const generateCaJson = await generateCa.json()
    assert.equal(generateCaJson.action, 'generate-ca')
    assert.equal(generateCaJson.lifecycle, 'active')
    assert.equal(generateCaJson.generated.certificate, true)
    assert.equal(generateCaJson.globalTrustManaged, false)
    assert.equal(generateCaJson.privateKeyProtection.modeOk, true)
    assert.equal(generateCaJson.privateKeyProtection.actualMode, '0600')
    assert.ok(existsSync(generateCaJson.paths.certificatePath))
    assert.ok(existsSync(generateCaJson.paths.privateKeyPath))

    const issueCert = await fetch(`${daemon.base}/tls/cert`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ host: 'api.example.com', days: 1 }),
    })
    assert.equal(issueCert.status, 200)
    const issueCertJson = await issueCert.json()
    assert.equal(issueCertJson.action, 'issue-cert')
    assert.equal(issueCertJson.lifecycle, 'active')
    assert.equal(issueCertJson.host, 'api.example.com')
    assert.equal(issueCertJson.generated.certificate, true)
    assert.equal(issueCertJson.generated.privateKey, true)
    assert.equal(issueCertJson.globalTrustManaged, false)
    assert.ok(existsSync(issueCertJson.paths.certificatePath))
    assert.ok(existsSync(issueCertJson.paths.privateKeyPath))

    const tlsStatus = await fetch(`${daemon.base}/tls/status`, { headers })
    assert.equal(tlsStatus.status, 200)
    const tlsStatusJson = await tlsStatus.json()
    assert.equal(tlsStatusJson.globalTrustManaged, false)
    assert.equal(tlsStatusJson.trustStoreAction, 'not-managed-by-guardd')
    assert.equal(tlsStatusJson.issued.count, 1)
    assert.equal(tlsStatusJson.issued.certificates[0].host, 'api.example.com')
    assert.ok(tlsStatusJson.onboarding.environmentVariables.includes('NODE_EXTRA_CA_CERTS'))

    const securityStatus = await fetch(`${daemon.base}/security/status`, { headers })
    assert.equal(securityStatus.status, 200)
    const securityStatusJson = await securityStatus.json()
    assert.equal(securityStatusJson.checks.some((check) => check.id === 'api-token-required' && check.ok === true), true)
    assert.equal(securityStatusJson.token.fingerprint, rotateTokenJson.auth.fingerprint)
    assert.equal(securityStatusJson.token.keychainDescriptor.invokedByGuardd, false)
    assert.equal(securityStatusJson.caKeyProtection.keychainDescriptor.invokedByGuardd, false)
    assert.equal(securityStatusJson.findings.some((finding) => finding.id === 'tls-ca-key-private'), false)

    const rotateCa = await fetch(`${daemon.base}/tls/ca`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'rotate', days: 1 }),
    })
    assert.equal(rotateCa.status, 200)
    const rotateCaJson = await rotateCa.json()
    assert.equal(rotateCaJson.action, 'rotate-ca')
    assert.equal(rotateCaJson.lifecycle, 'active')

    const revokeCa = await fetch(`${daemon.base}/tls/ca`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'revoke' }),
    })
    assert.equal(revokeCa.status, 200)
    const revokeCaJson = await revokeCa.json()
    assert.equal(revokeCaJson.action, 'revoke-ca')
    assert.equal(revokeCaJson.lifecycle, 'revoked')

    const tlsMutation = await fetch(`${daemon.base}/profiles/guard/tls`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ enabled: true }),
    })
    assert.equal(tlsMutation.status, 200)

    const tlsEvents = await fetch(`${daemon.base}/events?type=tls.changed&limit=1`, { headers })
    assert.equal(tlsEvents.status, 200)
    const tlsEventJson = await tlsEvents.json()
    assert.equal(tlsEventJson.events.length, 1)
    assert.equal(tlsEventJson.events[0].type, 'tls.changed')
    assert.equal(tlsEventJson.events[0].profile, 'guard')
    assert.equal(tlsEventJson.events[0].globalTrustManaged, false)
    assert.equal(tlsEventJson.events[0].after.enabled, true)

    const queriedTlsEvents = await fetch(`${daemon.base}/events/query?type=tls.changed&profile=guard&limit=5`, { headers })
    assert.equal(queriedTlsEvents.status, 200)
    const queriedTlsEventsJson = await queriedTlsEvents.json()
    assert.equal(queriedTlsEventsJson.events.length, 1)
    assert.equal(queriedTlsEventsJson.events[0].type, 'tls.changed')
    assert.equal(queriedTlsEventsJson.invalidLineCount, 1)
    assert.equal(queriedTlsEventsJson.tamperLineCount, 1)
    assert.equal(queriedTlsEventsJson.summary.byType.some((entry) => entry.key === 'tls.changed' && entry.count === 1), true)

    const alertOnce = await fetch(`${daemon.base}/alerts/decision`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'api.example.com',
        port: 443,
        action: 'allow',
        duration: 'once',
      }),
    })
    assert.equal(alertOnce.status, 200)
    const alertOnceJson = await alertOnce.json()
    assert.equal(alertOnceJson.decision.type, 'guard.alert.decision')
    assert.equal(alertOnceJson.decision.duration, 'once')
    assert.equal(alertOnceJson.decision.rulePersisted, false)

    const pendingAlert = await fetch(`${daemon.base}/alerts/pending`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'pending.example.com',
        port: 443,
        method: 'POST',
        path: '/v1/responses',
        timeoutMs: 5000,
      }),
    })
    assert.equal(pendingAlert.status, 201)
    const pendingAlertJson = await pendingAlert.json()
    assert.equal(pendingAlertJson.alert.status, 'pending')
    assert.equal(pendingAlertJson.alert.host, 'pending.example.com')
    assert.equal(pendingAlertJson.alert.method, 'POST')
    assert.equal(pendingAlertJson.alert.path, '/v1/responses')
    assert.equal(pendingAlertJson.alert.decisionRequest.operation.kind, 'http.request')
    assert.equal(pendingAlertJson.alert.decisionRequest.resource.kind, 'http')
    assert.equal(pendingAlertJson.alert.decisionRequest.resource.host, 'pending.example.com')
    assert.match(pendingAlertJson.alert.id, /^[0-9a-f-]{36}$/)
    assert.match(pendingAlertJson.alert.expiresAt, /^\d{4}-\d{2}-\d{2}T/)

    const pendingList = await fetch(`${daemon.base}/alerts/pending?limit=5`, { headers })
    assert.equal(pendingList.status, 200)
    const pendingListJson = await pendingList.json()
    assert.equal(pendingListJson.pendingCount, 1)
    assert.equal(pendingListJson.persisted, true)
    assert.match(pendingListJson.statePath, /pending-alerts\.json$/)
    assert.equal(pendingListJson.alerts.some((alert) => alert.id === pendingAlertJson.alert.id), true)

    await daemon.stop()
    daemon = await startGuarddForTest({
      policyRoot: tempRoot,
      eventLog,
      extraEnv: { GUARD_STATE_DIR: stateDir },
    })
    headers.authorization = `Bearer ${daemon.token}`
    const restoredPendingList = await fetch(`${daemon.base}/alerts/pending?limit=5`, { headers })
    assert.equal(restoredPendingList.status, 200)
    const restoredPendingListJson = await restoredPendingList.json()
    assert.equal(restoredPendingListJson.pendingCount, 1)
    assert.equal(restoredPendingListJson.alerts.some((alert) => alert.id === pendingAlertJson.alert.id), true)

    const resolvedPending = await fetch(`${daemon.base}/alerts/${pendingAlertJson.alert.id}/resolve`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'allow',
        duration: 'session',
        scope: 'path',
      }),
    })
    assert.equal(resolvedPending.status, 200)
    const resolvedPendingJson = await resolvedPending.json()
    assert.equal(resolvedPendingJson.decision.alertId, pendingAlertJson.alert.id)
    assert.equal(resolvedPendingJson.decision.duration, 'session')
    assert.equal(resolvedPendingJson.alert.status, 'resolved')
    assert.equal(resolvedPendingJson.alert.decision.action, 'allow')

    const sessionRules = await fetch(`${daemon.base}/rules?profile=guard`, { headers })
    assert.equal(sessionRules.status, 200)
    const sessionRulesJson = await sessionRules.json()
    assert.equal(sessionRulesJson.schemaVersion, 1)
    assert.equal(Array.isArray(sessionRulesJson.typedRules), true)
    assert.equal(sessionRulesJson.temporaryRules.some((rule) =>
      rule.lifetime === 'session' &&
      rule.layer === 'http' &&
      rule.scope === 'POST pending.example.com /v1/responses'
    ), true)

    const cachedPathAlert = await fetch(`${daemon.base}/alerts/pending`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'pending.example.com',
        port: 443,
        method: 'POST',
        path: '/v1/models',
        timeoutMs: 5000,
      }),
    })
    assert.equal(cachedPathAlert.status, 200)
    const cachedPathAlertJson = await cachedPathAlert.json()
    assert.equal(cachedPathAlertJson.cached, true)
    assert.equal(cachedPathAlertJson.decision.action, 'allow')
    assert.deepEqual(cachedPathAlertJson.decision.rule, {
      host: 'pending.example.com',
      methods: ['POST'],
      paths: ['/v1/*'],
    })

    const shortRuleAlert = await fetch(`${daemon.base}/alerts/pending`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'short-rule.example.com',
        port: 443,
        method: 'POST',
        path: '/v1/responses',
        timeoutMs: 5000,
      }),
    })
    assert.equal(shortRuleAlert.status, 201)
    const shortRuleAlertJson = await shortRuleAlert.json()
    const shortRuleResolve = await fetch(`${daemon.base}/alerts/${shortRuleAlertJson.alert.id}/resolve`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'allow',
        duration: '10s',
        scope: 'path',
      }),
    })
    assert.equal(shortRuleResolve.status, 200)
    const shortRuleResolveJson = await shortRuleResolve.json()
    assert.equal(shortRuleResolveJson.decision.duration, '10s')
    assert.match(shortRuleResolveJson.decision.expiresAt, /^\d{4}-\d{2}-\d{2}T/)

    const cachedShortRuleAlert = await fetch(`${daemon.base}/alerts/pending`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'short-rule.example.com',
        port: 443,
        method: 'POST',
        path: '/v1/models',
        timeoutMs: 5000,
      }),
    })
    assert.equal(cachedShortRuleAlert.status, 200)
    const cachedShortRuleAlertJson = await cachedShortRuleAlert.json()
    assert.equal(cachedShortRuleAlertJson.cached, true)
    assert.equal(cachedShortRuleAlertJson.decision.duration, '10s')

    await new Promise((resolveDone) => setTimeout(resolveDone, 10_500))
    const expiredShortRuleAlert = await fetch(`${daemon.base}/alerts/pending`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'short-rule.example.com',
        port: 443,
        method: 'POST',
        path: '/v1/models',
        timeoutMs: 5000,
      }),
    })
    assert.equal(expiredShortRuleAlert.status, 201)
    const expiredShortRuleAlertJson = await expiredShortRuleAlert.json()
    assert.equal(expiredShortRuleAlertJson.cached, undefined)
    assert.notEqual(expiredShortRuleAlertJson.alert.id, shortRuleAlertJson.alert.id)

    const resolvedList = await fetch(`${daemon.base}/alerts/pending?status=resolved&limit=5`, { headers })
    assert.equal(resolvedList.status, 200)
    const resolvedListJson = await resolvedList.json()
    assert.equal(resolvedListJson.alerts.some((alert) => alert.id === pendingAlertJson.alert.id), true)

    const expiringAlert = await fetch(`${daemon.base}/alerts/pending`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'expiring.example.com',
        timeoutMs: 1,
      }),
    })
    assert.equal(expiringAlert.status, 201)
    await new Promise((resolveDone) => setTimeout(resolveDone, 20))
    const expiredList = await fetch(`${daemon.base}/alerts/pending?status=expired&limit=5`, { headers })
    assert.equal(expiredList.status, 200)
    const expiredListJson = await expiredList.json()
    assert.equal(expiredListJson.alerts.some((alert) => alert.host === 'expiring.example.com'), true)

    const alertForever = await fetch(`${daemon.base}/alerts/decision`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'forever.example.com',
        action: 'deny',
        duration: 'forever',
      }),
    })
    assert.equal(alertForever.status, 200)
    const alertForeverJson = await alertForever.json()
    assert.equal(alertForeverJson.decision.rulePersisted, true)
    assert.equal(alertForeverJson.mutation.field, 'network.deniedDomains')

    const httpScopeDecision = await fetch(`${daemon.base}/alerts/decision`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        host: 'api.openai.com',
        method: 'POST',
        path: '/v1/responses',
        action: 'allow',
        duration: 'forever',
        scope: 'path',
      }),
    })
    assert.equal(httpScopeDecision.status, 200)
    const httpScopeDecisionJson = await httpScopeDecision.json()
    assert.equal(httpScopeDecisionJson.decision.field, 'network.httpRules')
    assert.deepEqual(httpScopeDecisionJson.mutation.value, {
      host: 'api.openai.com',
      methods: ['POST'],
      paths: ['/v1/*'],
    })

    const alerts = await fetch(`${daemon.base}/alerts?limit=5`, { headers })
    assert.equal(alerts.status, 200)
    const alertsJson = await alerts.json()
    assert.equal(alertsJson.events.some((event) => event.host === 'forever.example.com'), true)

    const index = await fetch(`${daemon.base}/events/index`, { headers })
    assert.equal(index.status, 200)
    const indexJson = await index.json()
    assert.equal(indexJson.schemaVersion, 2)
    assert.equal(indexJson.eventSchemaVersion, 1)
    assert.equal(indexJson.rebuild.completed, true)
    assert.equal(indexJson.rebuild.validLineCount >= 3, true)
    assert.equal(indexJson.rebuild.invalidLineCount, 1)
    assert.equal(indexJson.rebuild.tamperLineCount, 1)
    assert.equal(indexJson.integrity.invalidLineCount, 1)
    assert.equal(indexJson.integrity.tamperLineCount, 1)
    assert.equal(indexJson.summaries.byType.some((entry) => entry.key === 'seed' && entry.count === 3), true)
    assert.equal(indexJson.byType['guard.alert.decision'] >= 3, true)
    assert.equal(indexJson.byType['guard.alert.pending'] >= 2, true)
    assert.equal(indexJson.byType['guard.alert.resolved'] >= 1, true)
    assert.equal(indexJson.byType['guard.alert.expired'] >= 1, true)
    assert.equal(indexJson.alertDecisions >= 3, true)

    const integrity = await fetch(`${daemon.base}/events/integrity`, { headers })
    assert.equal(integrity.status, 200)
    const integrityJson = await integrity.json()
    assert.equal(integrityJson.ok, false)
    assert.equal(integrityJson.schemaVersion, 2)
    assert.equal(integrityJson.eventSchemaVersion, 1)
    assert.equal(integrityJson.invalidLineCount, 1)
    assert.equal(integrityJson.tamperLineCount, 1)
    assert.equal(integrityJson.issues.some((issue) => issue.reason === 'json_parse_failed'), true)
    assert.equal(integrityJson.issues.some((issue) => issue.reason === 'unsupported_schema_version'), true)
    assert.match(integrityJson.digest, /^sha256:/)

    const denyForEvaluation = await fetch(`${daemon.base}/profiles/guard/rules`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'add',
        field: 'network.deniedDomains',
        value: 'api.example.com',
      }),
    })
    assert.equal(denyForEvaluation.status, 200)

    const evaluationAllowed = await fetch(`${daemon.base}/policy/evaluate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ profile: 'guard', host: 'api.example.com' }),
    })
    assert.equal(evaluationAllowed.status, 200)
    const evaluationAllowedJson = await evaluationAllowed.json()
    assert.equal(evaluationAllowedJson.contractVersion, 1)
    assert.equal(evaluationAllowedJson.decision.allowed, false)
    assert.equal(evaluationAllowedJson.decision.reason, 'deniedDomains')
    assert.equal(evaluationAllowedJson.decision.contractVersion, 1)
    assert.equal(evaluationAllowedJson.decision.evaluator, 'guard-policy')
    assert.equal(evaluationAllowedJson.normalizedDecision.decisionRequest.operation.kind, 'network.connect')

    const sync = await fetch(`${daemon.base}/extension/sync`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        profile: 'guard',
        mode: 'strict-deny',
      }),
    })
    assert.equal(sync.status, 200)
    const syncJson = await sync.json()
    assert.equal(syncJson.syncVersion, 1)
    assert.equal(syncJson.configured, true)
    assert.equal(syncJson.manifest.profile, 'guard')
    assert.equal(syncJson.manifest.fallback.stalePolicy, 'strict-deny')
    assert.match(syncJson.manifest.policyDigest, /^sha256:[0-9a-f]{64}$/)
    assert.equal(syncJson.validPolicyDigest, true)
    assert.equal(syncJson.invalidated, false)
    assert.ok(existsSync(syncJson.paths.manifestPath))
    assert.ok(existsSync(syncJson.paths.policyPath))
    const syncedPolicy = JSON.parse(readFileSync(syncJson.paths.policyPath, 'utf8'))
    assert.equal(syncedPolicy.profile, 'guard')
    assert.equal(syncedPolicy.contractVersion, 1)
    assert.equal(syncedPolicy.syncVersion, 1)
    assert.equal(syncedPolicy.decisionContract.evaluator, 'guard-policy')
    assert.equal(syncedPolicy.network.deniedDomains.includes('api.example.com'), true)

    const syncState = await fetch(`${daemon.base}/extension/sync`, { headers })
    assert.equal(syncState.status, 200)
    const syncStateJson = await syncState.json()
    assert.equal(syncStateJson.manifest.sequence, syncJson.sequence)
    assert.equal(syncStateJson.validPolicyDigest, true)
    assert.equal(syncStateJson.status.installed, true)
    assert.equal(syncStateJson.status.running, true)
    assert.equal(syncStateJson.status.fallbackMode, 'strict-deny')

    const invalidateSync = await fetch(`${daemon.base}/extension/sync`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'invalidate', reason: 'test-invalidation' }),
    })
    assert.equal(invalidateSync.status, 200)
    const invalidateSyncJson = await invalidateSync.json()
    assert.equal(invalidateSyncJson.action, 'extension-sync-invalidate')
    assert.equal(invalidateSyncJson.invalidated, true)
    assert.equal(invalidateSyncJson.manifest.invalidateReason, 'test-invalidation')
    assert.equal(invalidateSyncJson.manifest.sequence, syncJson.sequence + 1)

    const unbounded = await fetch(`${daemon.base}/events/truncate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ keepBytes: 1024 * 1024 + 1 }),
    })
    assert.equal(unbounded.status, 400)
    const unboundedJson = await unbounded.json()
    assert.equal(unboundedJson.error, 'truncate_failed')

    const truncate = await fetch(`${daemon.base}/events/truncate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ keepBytes: 0 }),
    })
    assert.equal(truncate.status, 200)
    const truncateJson = await truncate.json()
    assert.equal(truncateJson.type, 'daemon.log.truncated')
    assert.equal(truncateJson.keepBytes, 0)
    assert.equal(truncateJson.maxKeepBytes, 1024 * 1024)

    const afterEvents = await fetch(`${daemon.base}/events?type=daemon.log.truncated&limit=1`, { headers })
    assert.equal(afterEvents.status, 200)
    const afterEventJson = await afterEvents.json()
    assert.equal(afterEventJson.events.length, 1)
    assert.equal(afterEventJson.events[0].path, eventLog)

    const afterState = await fetch(`${daemon.base}/state`, { headers })
    assert.equal(afterState.status, 200)
    const afterStateJson = await afterState.json()
    assert.equal(afterStateJson.tail.retention.truncated, true)
    assert.equal(afterStateJson.tail.retention.lastTruncation.eventLogPath, eventLog)
    assert.equal(afterStateJson.tail.retention.lastTruncation.keepBytes, 0)
    assert.ok(existsSync(afterStateJson.tail.metadataPath))
    const persistedState = JSON.parse(readFileSync(afterStateJson.tail.metadataPath, 'utf8'))
    assert.equal(persistedState.service, 'guardd')
    assert.equal(persistedState.schemaVersion, 2)
    assert.equal(persistedState.eventSchemaVersion, 1)
    assert.equal(persistedState.migrations[0].to, 2)
    assert.equal(persistedState.cursor.eventLogPath, eventLog)
    assert.equal(persistedState.retention.truncated, true)
  } finally {
    await daemon?.stop()
    rmSync(tempRoot, { recursive: true, force: true })
  }
})

test('guardd recovers event cursor and recent events across restart', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guardd-cursor-recovery-'))
  const guardDir = resolve(tempRoot, '.guard')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const stateDir = resolve(tempRoot, 'state')
  let daemon = null

  try {
    mkdirSync(guardDir, { recursive: true })
    writeFileSync(
      resolve(guardDir, 'guard.json'),
      JSON.stringify({ network: { allowedDomains: [] }, filesystem: {} }, null, 2) + '\n',
    )
    writeFileSync(
      eventLog,
      [
        JSON.stringify({ schemaVersion: 1, type: 'seed', n: 1 }),
        JSON.stringify({ schemaVersion: 1, type: 'seed', n: 2 }),
      ].join('\n') + '\n',
    )

    daemon = await startGuarddForTest({
      policyRoot: tempRoot,
      eventLog,
      extraArgs: ['--max-events', '2'],
      extraEnv: { GUARD_STATE_DIR: stateDir },
    })
    const headers = { authorization: `Bearer ${daemon.token}` }

    const firstState = await fetch(`${daemon.base}/state`, { headers })
    assert.equal(firstState.status, 200)
    const firstStateJson = await firstState.json()
    assert.equal(firstStateJson.tail.recovery.mode, 'tail-scan')
    assert.equal(firstStateJson.tail.retainedEventCount, 2)
    assert.equal(firstStateJson.tail.offset, readFileSync(eventLog).byteLength)

    await daemon.stop()
    daemon = null

    writeFileSync(
      eventLog,
      `${readFileSync(eventLog, 'utf8')}${JSON.stringify({ schemaVersion: 1, type: 'missed', n: 3 })}\n`,
    )

    daemon = await startGuarddForTest({
      policyRoot: tempRoot,
      eventLog,
      extraArgs: ['--max-events', '2'],
      extraEnv: { GUARD_STATE_DIR: stateDir },
    })

    const secondState = await fetch(`${daemon.base}/state`, { headers })
    assert.equal(secondState.status, 200)
    const secondStateJson = await secondState.json()
    assert.equal(secondStateJson.tail.recovery.mode, 'cursor')
    assert.equal(secondStateJson.tail.recovery.recovered, true)
    assert.equal(secondStateJson.tail.recovery.unreadBytes > 0, true)
    assert.equal(secondStateJson.tail.offset, readFileSync(eventLog).byteLength)

    const missedEvents = await fetch(`${daemon.base}/events?type=missed&limit=1`, { headers })
    assert.equal(missedEvents.status, 200)
    const missedEventsJson = await missedEvents.json()
    assert.equal(missedEventsJson.events.length, 1)
    assert.equal(missedEventsJson.events[0].n, 3)

    const persistedState = JSON.parse(readFileSync(resolve(stateDir, 'daemon-state.json'), 'utf8'))
    assert.equal(persistedState.cursor.offset, readFileSync(eventLog).byteLength)
    assert.equal(persistedState.recovery.mode, 'cursor')
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

test('sandbox denial log parser extracts file and process denials tagged by Guard', () => {
  const fileEvent = parseSandboxDenialMessage(
    [
      'Sandbox: cat(33929) deny(1) file-read-data /Users/example/.ssh/id_rsa',
      'guard:test-tag',
    ].join('\n'),
    'guard:test-tag',
  )
  assert.equal(fileEvent.category, 'filesystem')
  assert.equal(fileEvent.operation, 'file-read-data')
  assert.equal(fileEvent.actor, 'cat')
  assert.equal(fileEvent.pid, 33929)
  assert.equal(fileEvent.path, '/Users/example/.ssh/id_rsa')
  assert.equal(fileEvent.result, 'deny')
  assert.equal(fileEvent.severity, 'high')
  assert.equal(fileEvent.sensitivity, 'ssh-private-key')
  assert.equal(fileEvent.notificationRecommended, true)

  const processEvent = parseSandboxDenialMessage(
    [
      'Sandbox: node(34055) deny(1) process-exec /bin/bash',
      'guard:test-tag',
    ].join('\n'),
    'guard:test-tag',
  )
  assert.equal(processEvent.category, 'process')
  assert.equal(processEvent.operation, 'process-exec')
  assert.equal(processEvent.executablePath, '/bin/bash')

  assert.equal(
    parseSandboxDenialMessage('Sandbox: cat(1) deny(1) file-read-data /tmp/x', 'guard:test-tag'),
    null,
  )
})

test('sandbox denial sensitivity classifies canaries and credentials without alerting on ordinary env files', () => {
  assert.deepEqual(
    classifySandboxDenialSensitivity({ operation: 'file-read-data', target: '/tmp/.guard-canary/aws-token' }),
    {
      severity: 'high',
      sensitivity: 'canary-file',
      reason: 'canary-file-access',
      notify: true,
    },
  )
  assert.deepEqual(
    classifySandboxDenialSensitivity({ operation: 'file-read-data', target: '/Users/example/.aws/credentials' }),
    {
      severity: 'high',
      sensitivity: 'credential-file',
      reason: 'credential-file-read',
      notify: true,
    },
  )
  assert.deepEqual(
    classifySandboxDenialSensitivity({ operation: 'file-read-data', target: '/Users/example/.config/gh/hosts.yml' }),
    {
      severity: 'high',
      sensitivity: 'credential-file',
      reason: 'credential-file-read',
      notify: true,
    },
  )
  assert.deepEqual(
    classifySandboxDenialSensitivity({ operation: 'file-read-data', target: '/Users/example/.terraform.d/credentials.tfrc.json' }),
    {
      severity: 'high',
      sensitivity: 'credential-file',
      reason: 'credential-file-read',
      notify: true,
    },
  )
  assert.deepEqual(
    classifySandboxDenialSensitivity({ operation: 'file-read-data', target: '/Users/example/Documents/passwords.kdbx' }),
    {
      severity: 'high',
      sensitivity: 'credential-database',
      reason: 'credential-database-read',
      notify: true,
    },
  )
  assert.deepEqual(
    classifySandboxDenialSensitivity({ operation: 'file-read-data', target: '/Users/example/project/.env' }),
    {
      severity: 'medium',
      sensitivity: 'env-file',
      reason: 'env-file-access',
      notify: false,
    },
  )
})

test('guard records tagged macOS sandbox denial events without log polling', {
  skip: process.platform !== 'darwin' || !existsSync('/usr/bin/sandbox-exec') || !existsSync('/usr/bin/log'),
}, async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-sandbox-denial-'))
  const projectRoot = resolve(tempRoot, 'project')
  const secretRoot = resolve(tempRoot, 'secret')
  mkdirSync(resolve(projectRoot, '.guard'), { recursive: true })
  mkdirSync(secretRoot, { recursive: true })
  const profilePath = resolve(projectRoot, '.guard/guard.json')
  const eventLog = resolve(tempRoot, 'events.jsonl')
  const blocked = resolve(secretRoot, '.guard-canary-secret.txt')
  writeFileSync(blocked, 'secret\n')
  const blockedReal = realpathSync(blocked)
  writeFileSync(
    profilePath,
    JSON.stringify({
      networkUnrestricted: true,
      filesystem: {
        allowRead: [projectRoot],
        allowWrite: [projectRoot],
        denyRead: [blocked],
        denyWrite: [],
      },
    }),
  )

  try {
    const result = spawnSync(
      guard,
      ['/bin/cat', blocked],
      {
        cwd: projectRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          GUARD_EVENT_LOG: eventLog,
          GUARD_SANDBOX_LOG_TAG: 'guard:test-denial-event',
          GUARD_SANDBOX_DENIAL_LOG_STARTUP_MS: '500',
          GUARD_BANNER: 'compact',
          GUARD_QUIET: '',
        },
        timeout: 15000,
      },
    )
    assert.notEqual(result.status, 0)
    assert.match(`${result.stderr}\n${result.stdout}`, /Operation not permitted|permission/i)

    const deadline = Date.now() + 5000
    let events = []
    while (Date.now() < deadline) {
      if (existsSync(eventLog)) {
        events = readFileSync(eventLog, 'utf8')
          .split(/\r?\n/)
          .filter(Boolean)
          .map((line) => JSON.parse(line))
      }
      if (events.some((event) =>
        event.type === 'sandbox.denial' &&
        event.operation === 'file-read-data' &&
        event.path === blockedReal &&
        event.severity === 'high' &&
        event.notificationRecommended === true &&
        event.ruleTag === 'guard:test-denial-event'
      )) {
        return
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100))
    }
    assert.fail(`missing sandbox.denial event in ${eventLog}\n${JSON.stringify(events, null, 2)}`)
  } finally {
    rmSync(tempRoot, { force: true, recursive: true })
  }
})

test('guard records tagged macOS subprocess denial events without an extension', {
  skip: process.platform !== 'darwin' || !existsSync('/usr/bin/sandbox-exec') || !existsSync('/usr/bin/log'),
}, async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-sandbox-exec-denial-'))
  const projectRoot = resolve(tempRoot, 'project')
  mkdirSync(resolve(projectRoot, '.guard'), { recursive: true })
  writeFileSync(
    resolve(projectRoot, '.guard/guard.json'),
    JSON.stringify({
      networkUnrestricted: true,
      filesystem: {
        allowRead: [projectRoot],
        allowWrite: [projectRoot],
        denyRead: [],
        denyWrite: [],
      },
      process: {
        denyByDefault: true,
        allowedExecutables: ['/bin/sh'],
        blockRiskyChildExecutables: false,
      },
    }),
  )
  const eventLog = resolve(tempRoot, 'events.jsonl')

  try {
    const result = spawnSync(
      guard,
      ['/bin/sh', '-c', '/bin/date'],
      {
        cwd: projectRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          GUARD_EVENT_LOG: eventLog,
          GUARD_SANDBOX_LOG_TAG: 'guard:test-exec-denial-event',
          GUARD_SANDBOX_DENIAL_LOG_STARTUP_MS: '500',
          GUARD_BANNER: 'compact',
          GUARD_QUIET: '',
        },
        timeout: 15000,
      },
    )
    assert.notEqual(result.status, 0)

    const deadline = Date.now() + 5000
    let events = []
    while (Date.now() < deadline) {
      if (existsSync(eventLog)) {
        events = readFileSync(eventLog, 'utf8')
          .split(/\r?\n/)
          .filter(Boolean)
          .map((line) => JSON.parse(line))
      }
      if (events.some((event) =>
        event.type === 'sandbox.denial' &&
        event.category === 'process' &&
        String(event.operation || '').startsWith('process-exec') &&
        event.executablePath === '/bin/date' &&
        event.ruleTag === 'guard:test-exec-denial-event'
      )) {
        return
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100))
    }
    assert.fail(`missing process sandbox.denial event in ${eventLog}\n${JSON.stringify(events, null, 2)}`)
  } finally {
    rmSync(tempRoot, { force: true, recursive: true })
  }
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
  assert.match(compact.stderr, /^guard ok  net ask active  process children allowed, risky tools blocked  secrets protected  run=/)
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
      allowLoopbackHighPorts: true,
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
    assert.match(result.stdout, /removed-loopback-high-ports/)
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

test('init-agent creates Guard profile authoring notes for coding agents', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-init-agent-'))
  const result = spawnSync(guard, ['init-agent'], {
    cwd: tempRoot,
    encoding: 'utf8',
  })

  expectOk(result)
  const created = resolve(tempRoot, 'AGENTS.md')
  assert.equal(existsSync(created), true)
  const content = readFileSync(created, 'utf8')
  assert.match(content, /Guard Profile Authoring Notes/)
  assert.match(content, /guard profile doctor/)
  assert.match(content, /networkUnrestricted/)
})

test('init-agent refuses to overwrite existing notes without --force', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'guard-init-agent-existing-'))
  const target = resolve(tempRoot, 'AGENTS.md')
  writeFileSync(target, 'custom notes\n')

  const denied = spawnSync(guard, ['init-agent'], {
    cwd: tempRoot,
    encoding: 'utf8',
  })
  assert.notEqual(denied.status, 0)
  assert.match(denied.stderr, /refusing to overwrite/)
  assert.equal(readFileSync(target, 'utf8'), 'custom notes\n')

  const forced = spawnSync(guard, ['init-agent', '--force'], {
    cwd: tempRoot,
    encoding: 'utf8',
  })
  expectOk(forced)
  assert.match(readFileSync(target, 'utf8'), /Guard Profile Authoring Notes/)
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
