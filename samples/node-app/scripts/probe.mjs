import { mkdirSync, readdirSync, readFileSync, watch, writeFileSync } from 'node:fs'
import { connect, createServer } from 'node:net'
import { URL } from 'node:url'

const [action, value] = process.argv.slice(2)

const connectSocket = (options) =>
  new Promise((resolve, reject) => {
    const socket = connect(options)
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

const proxyUrl = (envName) => {
  const value = process.env[envName] || process.env[envName.toLowerCase()]
  if (!value) throw new Error(`${envName} is not set`)
  return new URL(value)
}

const socketHost = (url) => url.hostname.replace(/^\[|\]$/g, '')

const requestThroughConnect = async (targetUrl) => {
  const target = new URL(targetUrl)
  const proxy = proxyUrl('HTTPS_PROXY')
  const socket = await connectSocket({
    host: proxy.hostname,
    port: Number(proxy.port || 80),
  })
  socket.write(
    `CONNECT ${target.hostname}:${target.port || 80} HTTP/1.1\r\nHost: ${target.host}\r\n\r\n`,
  )
  const connectResponse = await readUntil(socket, Buffer.from('\r\n\r\n'))
  if (!/^HTTP\/1\.[01] 200\b/.test(connectResponse.toString('utf8'))) {
    throw new Error(`CONNECT failed: ${connectResponse.toString('utf8').split('\r\n')[0]}`)
  }
  socket.write(`GET ${target.pathname || '/'} HTTP/1.1\r\nHost: ${target.host}\r\nConnection: close\r\n\r\n`)
  const response = await readUntil(socket, Buffer.from('\r\n\r\n'))
  const chunks = [response]
  for await (const chunk of socket) {
    chunks.push(chunk)
  }
  process.stdout.write(Buffer.concat(chunks).toString('utf8'))
}

const socksConnect = async (target) => {
  const proxy = proxyUrl('ALL_PROXY')
  const socket = await connectSocket({
    host: proxy.hostname,
    port: Number(proxy.port),
  })
  socket.write(Buffer.from([0x05, 0x01, 0x00]))
  const greeting = await readUntil(socket, Buffer.from([0x05, 0x00]))
  if (greeting.length < 2 || greeting[1] !== 0x00) {
    throw new Error('SOCKS greeting failed')
  }

  const host = Buffer.from(target.hostname)
  const request = Buffer.alloc(7 + host.length)
  request[0] = 0x05
  request[1] = 0x01
  request[2] = 0x00
  request[3] = 0x03
  request[4] = host.length
  host.copy(request, 5)
  request.writeUInt16BE(Number(target.port || 80), 5 + host.length)
  socket.write(request)
  const response = await readUntil(socket, Buffer.from([0x05, 0x00]))
  if (response.length < 2 || response[1] !== 0x00) {
    throw new Error('SOCKS connect failed')
  }
  return socket
}

switch (action) {
  case 'read-file':
    readFileSync(value, 'utf8')
    break
  case 'read-dir':
    readdirSync(value)
    break
  case 'read-dir-if-exists':
    try {
      readdirSync(value)
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        break
      }
      throw err
    }
    break
  case 'write-file':
    writeFileSync(value, 'ok\n')
    break
  case 'write-project':
    mkdirSync('.guard-test', { recursive: true })
    writeFileSync('.guard-test/out.txt', 'ok\n')
    break
  case 'write-tmp':
    writeFileSync(`${process.env.TMPDIR}/tmp-ok.txt`, 'ok\n')
    readFileSync(`${process.env.TMPDIR}/tmp-ok.txt`, 'utf8')
    break
  case 'read-home-link':
    process.stdout.write(readFileSync(`${process.env.HOME}/${value}`, 'utf8'))
    break
  case 'fs-watch': {
    const watcher = watch(value || '.', () => {})
    await new Promise((resolve) => setTimeout(resolve, 200))
    watcher.close()
    process.stdout.write('watch-ok\n')
    break
  }
  case 'unix-socket': {
    const socketPath = value === 'tmpdir' ? `${process.env.TMPDIR}/probe.sock` : value
    await new Promise((resolve, reject) => {
      const server = createServer()
      server.on('error', reject)
      server.listen(socketPath, () => {
        server.close(resolve)
      })
    })
    break
  }
  case 'tcp-listen': {
    await new Promise((resolve, reject) => {
      const server = createServer()
      server.on('error', reject)
      server.listen({ host: value || '127.0.0.1', port: 0 }, () => {
        server.close(resolve)
      })
    })
    process.stdout.write('listen-ok\n')
    break
  }
  case 'direct-tcp': {
    const target = new URL(value)
    const socket = await connectSocket({
      host: socketHost(target),
      port: Number(target.port),
    })
    socket.end()
    process.stdout.write('direct-ok\n')
    break
  }
  case 'http-connect':
    await requestThroughConnect(value)
    break
  case 'socks-http': {
    const target = new URL(value)
    const socket = await socksConnect(target)
    socket.write(`GET ${target.pathname || '/'} HTTP/1.1\r\nHost: ${target.host}\r\nConnection: close\r\n\r\n`)
    const chunks = []
    for await (const chunk of socket) {
      chunks.push(chunk)
    }
    process.stdout.write(Buffer.concat(chunks).toString('utf8'))
    break
  }
  case 'node-fetch': {
    const response = await fetch(value)
    process.stdout.write(await response.text())
    break
  }
  case 'websocket': {
    await new Promise((resolve, reject) => {
      const ws = new WebSocket(value)
      const timeout = setTimeout(() => reject(new Error('WebSocket timed out')), 5000)
      ws.addEventListener('open', () => {
        clearTimeout(timeout)
        ws.close()
        process.stdout.write('websocket-ok\n')
        resolve()
      })
      ws.addEventListener('error', () => {
        clearTimeout(timeout)
        reject(new Error('WebSocket failed'))
      })
    })
    break
  }
  case 'env-json':
    process.stdout.write(JSON.stringify({
      guardProjectDir: process.env.GUARD_PROJECT_DIR,
      guardCwd: process.env.GUARD_CWD,
      guardRunDir: process.env.GUARD_RUN_DIR,
      guardSocksProxy: process.env.GUARD_SOCKS_PROXY,
      guardSshProxyCommand: process.env.GUARD_SSH_PROXY_COMMAND,
      allProxy: process.env.ALL_PROXY,
      gitSshCommand: process.env.GIT_SSH_COMMAND,
    }))
    break
  case 'runtime-config-json':
    process.stdout.write(readFileSync(`${process.env.TMPDIR}/config.json`, 'utf8'))
    break
  default:
    throw new Error(`unknown probe action: ${action}`)
}
