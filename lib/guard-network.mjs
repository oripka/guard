#!/usr/bin/env node

import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { readFile } from 'node:fs/promises'
import {
  connect as netConnect,
  createServer as createNetServer,
  isIP,
} from 'node:net'
import {
  createSecureContext,
  TLSSocket,
} from 'node:tls'
import { URL } from 'node:url'

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'proxy-connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

const normalizeHost = (value) => {
  if (typeof value !== 'string') return ''
  let host = value.trim().toLowerCase()
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1)
  }
  if (host.endsWith('.')) {
    host = host.slice(0, -1)
  }
  return host
}

const isValidHost = (value) => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    return false
  }
  return !/[\u0000-\u001f\u007f\s/\\]/.test(value)
}

const domainPatternToRegex = (pattern) =>
  new RegExp(
    '^' +
      normalizeHost(pattern)
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*') +
      '$',
  )

const hostMatchesPattern = (host, pattern) => {
  const normalizedHost = normalizeHost(host)
  const normalizedPattern = normalizeHost(pattern)
  if (!normalizedHost || !normalizedPattern) return false
  if (!normalizedPattern.includes('*')) {
    return normalizedHost === normalizedPattern
  }
  return domainPatternToRegex(normalizedPattern).test(normalizedHost)
}

const stripHopByHop = (headers = {}) => {
  const next = { ...headers }
  for (const key of Object.keys(next)) {
    if (HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      delete next[key]
    }
  }
  return next
}

const parseConnectTarget = (target) => {
  const match =
    /^\[([^\]]+)\]:(\d+)$/.exec(target) ?? /^([^:]+):(\d+)$/.exec(target)
  if (!match) return null
  const port = Number(match[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  return { host: match[1], port }
}

const connectUpstream = (host, port) =>
  new Promise((resolve, reject) => {
    const socket = netConnect({ host, port })
    const onError = (error) => {
      socket.destroy()
      reject(error)
    }
    socket.once('error', onError)
    socket.once('connect', () => {
      socket.off('error', onError)
      resolve(socket)
    })
  })

const sendProxyError = (socket, status, message) => {
  socket.end(
    `HTTP/1.1 ${status} ${message}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${message}`,
  )
}

const readPemPair = async ({ certificatePath, privateKeyPath }) => ({
  cert: await readFile(certificatePath, 'utf8'),
  key: await readFile(privateKeyPath, 'utf8'),
  certificatePath,
  privateKeyPath,
})

export const createGuarddTlsCertificateIssuer = ({
  baseUrl = process.env.GUARDD_URL ||
    `http://${process.env.GUARDD_HOST || '127.0.0.1'}:${process.env.GUARDD_PORT || 8765}`,
  token = process.env.GUARDD_API_TOKEN || '',
  days = 7,
  fetchImpl = globalThis.fetch,
} = {}) => {
  if (typeof fetchImpl !== 'function') {
    throw new Error('guardd TLS certificate issuer requires fetch support')
  }
  const cache = new Map()

  return {
    async issue(host) {
      const normalizedHost = normalizeHost(host)
      if (!isValidHost(normalizedHost)) {
        throw new Error(`invalid TLS host: ${host}`)
      }
      if (!cache.has(normalizedHost)) {
        cache.set(
          normalizedHost,
          (async () => {
            const response = await fetchImpl(new URL('/tls/cert', baseUrl), {
              method: 'POST',
              headers: {
                'content-type': 'application/json',
                ...(token ? { authorization: `Bearer ${token}` } : {}),
              },
              body: JSON.stringify({ host: normalizedHost, days }),
            })
            if (!response.ok) {
              const body = await response.text().catch(() => '')
              throw new Error(`guardd /tls/cert failed for ${normalizedHost}: ${response.status} ${body}`)
            }
            const issued = await response.json()
            return readPemPair(issued.paths || {})
          })(),
        )
      }
      return cache.get(normalizedHost)
    },
  }
}

export const createLocalTlsCertificateIssuer = ({ issueCertificate }) => {
  if (typeof issueCertificate !== 'function') {
    throw new Error('local TLS certificate issuer requires issueCertificate(host)')
  }
  const cache = new Map()
  return {
    async issue(host) {
      const normalizedHost = normalizeHost(host)
      if (!isValidHost(normalizedHost)) {
        throw new Error(`invalid TLS host: ${host}`)
      }
      if (!cache.has(normalizedHost)) {
        cache.set(
          normalizedHost,
          Promise.resolve(issueCertificate(normalizedHost)).then((issued) => {
            if (issued?.cert && issued?.key) return issued
            return readPemPair(issued?.paths || issued || {})
          }),
        )
      }
      return cache.get(normalizedHost)
    },
  }
}

export const createDomainFilter = (network = {}, options = {}) => {
  const allowedDomains = Array.isArray(network.allowedDomains)
    ? network.allowedDomains
    : []
  const deniedDomains = Array.isArray(network.deniedDomains)
    ? network.deniedDomains
    : []
  const allowedHosts = new Set()
  const deniedHosts = new Set()
  const pendingHosts = new Map()
  const record = (event) => {
    if (typeof options.onDecision === 'function') {
      options.onDecision(event)
    }
  }

  return async (host, port) => {
    if (!isValidHost(host)) {
      record({ host, port, allowed: false, reason: 'invalid-host' })
      return false
    }

    const normalizedHost = normalizeHost(host)
    if (!normalizedHost) {
      record({ host, port, allowed: false, reason: 'invalid-host' })
      return false
    }

    if (deniedHosts.has(normalizedHost)) {
      record({ host: normalizedHost, port, allowed: false, reason: 'cached-deny' })
      return false
    }
    if (allowedHosts.has(normalizedHost)) {
      record({ host: normalizedHost, port, allowed: true, reason: 'cached-allow' })
      return true
    }

    const allowed =
      allowedDomains.length > 0 &&
      allowedDomains.some((pattern) => hostMatchesPattern(normalizedHost, pattern))
    const denied = deniedDomains.some((pattern) =>
      hostMatchesPattern(normalizedHost, pattern),
    )
    if (denied) {
      record({ host: normalizedHost, port, allowed: false, reason: 'deniedDomains' })
      return false
    }
    if (allowed) {
      record({ host: normalizedHost, port, allowed: true, reason: 'allowedDomains' })
      return true
    }

    if (typeof options.ask !== 'function') {
      record({ host: normalizedHost, port, allowed: false, reason: 'default-deny' })
      return false
    }

    if (!pendingHosts.has(normalizedHost)) {
      pendingHosts.set(
        normalizedHost,
        Promise.resolve(options.ask(normalizedHost, port))
          .then(Boolean)
          .then((allow) => {
            if (allow) {
              allowedHosts.add(normalizedHost)
            } else {
              deniedHosts.add(normalizedHost)
            }
            record({
              host: normalizedHost,
              port,
              allowed: allow,
              reason: allow ? 'ask-allow' : 'ask-deny',
            })
            return allow
          })
          .finally(() => {
            pendingHosts.delete(normalizedHost)
          }),
      )
    }

    return pendingHosts.get(normalizedHost)
  }
}

export const buildProxyEnv = ({ httpPort, socksPort }) => {
  const host = 'localhost'
  const entries = []
  const noProxy = [
    'localhost',
    '127.0.0.1',
    '::1',
    '*.local',
    '.local',
    '169.254.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ].join(',')

  entries.push(`NO_PROXY=${noProxy}`)
  entries.push(`no_proxy=${noProxy}`)

  if (httpPort) {
    const value = `http://${host}:${httpPort}`
    entries.push(`HTTP_PROXY=${value}`)
    entries.push(`HTTPS_PROXY=${value}`)
    entries.push(`http_proxy=${value}`)
    entries.push(`https_proxy=${value}`)
    entries.push(`DOCKER_HTTP_PROXY=${value}`)
    entries.push(`DOCKER_HTTPS_PROXY=${value}`)
    entries.push(`CLOUDSDK_PROXY_TYPE=http`)
    entries.push(`CLOUDSDK_PROXY_ADDRESS=${host}`)
    entries.push(`CLOUDSDK_PROXY_PORT=${httpPort}`)
  }

  if (socksPort) {
    const socksValue = `socks5h://${host}:${socksPort}`
    const sshProxyCommand = `nc -X 5 -x ${host}:${socksPort} %h %p`
    entries.push(`GUARD_SOCKS_PROXY=${host}:${socksPort}`)
    entries.push(`GUARD_SSH_PROXY_COMMAND=${sshProxyCommand}`)
    entries.push(`ALL_PROXY=${socksValue}`)
    entries.push(`all_proxy=${socksValue}`)
    entries.push(`FTP_PROXY=${socksValue}`)
    entries.push(`ftp_proxy=${socksValue}`)
    entries.push(`GRPC_PROXY=${socksValue}`)
    entries.push(`grpc_proxy=${socksValue}`)
    entries.push(`RSYNC_PROXY=${host}:${socksPort}`)
    entries.push(`GIT_SSH_COMMAND=ssh -o ProxyCommand='${sshProxyCommand}'`)
  }

  return entries
}

export const startHttpProxy = async ({
  filter,
  tlsIntercept = false,
  tlsCertificateIssuer = null,
  upstreamTls = {},
  requestFilter = null,
} = {}) => {
  const server = createHttpServer()
  const decryptedServer = createHttpServer(async (req, res) => {
    try {
      const target = req.socket.guardTlsTarget
      if (!target) {
        res.writeHead(502, { 'content-type': 'text/plain' })
        res.end('Missing TLS target')
        return
      }
      const requestPath = req.url || '/'
      const allowed = typeof requestFilter === 'function'
        ? await requestFilter({
            protocol: 'https:',
            host: target.host,
            port: target.port,
            method: req.method || 'GET',
            path: requestPath,
            headers: req.headers,
          })
        : true
      if (!allowed) {
        res.writeHead(403, { 'content-type': 'text/plain' })
        res.end('Connection blocked by network allowlist')
        return
      }

      const proxyReq = httpsRequest(
        {
          hostname: target.host,
          port: target.port,
          servername: isIP(target.host) ? undefined : target.host,
          ca: upstreamTls.ca,
          rejectUnauthorized: upstreamTls.rejectUnauthorized !== false,
          method: req.method,
          path: requestPath,
          headers: {
            ...stripHopByHop(req.headers),
            host: req.headers.host || `${target.host}:${target.port}`,
          },
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 502, stripHopByHop(proxyRes.headers))
          proxyRes.pipe(res)
        },
      )

      proxyReq.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain' })
          res.end('Bad Gateway')
        } else {
          res.destroy()
        }
      })

      req.pipe(proxyReq)
    } catch {
      res.writeHead(502, { 'content-type': 'text/plain' })
      res.end('Bad Gateway')
    }
  })

  server.on('upgrade', async (req, socket, head) => {
    socket.on('error', () => {})
    try {
      const url = new URL(req.url)
      const host = normalizeHost(url.hostname)
      const port = url.port ? Number(url.port) : url.protocol === 'wss:' ? 443 : 80

      if (!(await filter(host, port))) {
        socket.end(
          'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nConnection blocked by network allowlist',
        )
        return
      }

      const upstream = await connectUpstream(host, port)
      upstream.on('error', () => socket.destroy())
      socket.on('error', () => upstream.destroy())

      const headers = {
        ...req.headers,
        host: url.host,
      }
      const headerLines = Object.entries(headers)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) =>
          Array.isArray(value)
            ? value.map((item) => `${key}: ${item}`).join('\r\n')
            : `${key}: ${value}`,
        )
        .join('\r\n')
      upstream.write(
        `${req.method || 'GET'} ${url.pathname}${url.search} HTTP/1.1\r\n${headerLines}\r\n\r\n`,
      )
      if (head.length > 0) {
        upstream.write(head)
      }
      upstream.pipe(socket)
      socket.pipe(upstream)
    } catch {
      socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
    }
  })

  server.on('connect', async (req, socket, head) => {
    socket.on('error', () => {})
    try {
      const target = parseConnectTarget(req.url || '')
      if (!target || !(await filter(target.host, target.port))) {
        sendProxyError(socket, '403', 'Connection blocked by network allowlist')
        return
      }

      if (tlsIntercept && tlsCertificateIssuer) {
        const issued = await tlsCertificateIssuer.issue(target.host)
        const secureContext = createSecureContext({
          cert: issued.cert,
          key: issued.key,
        })
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        const tlsSocket = new TLSSocket(socket, {
          isServer: true,
          secureContext,
        })
        tlsSocket.guardTlsTarget = target
        tlsSocket.on('error', () => socket.destroy())
        if (head.length > 0) {
          tlsSocket.unshift(head)
        }
        decryptedServer.emit('connection', tlsSocket)
        return
      }

      const upstream = await connectUpstream(target.host, target.port)
      upstream.on('error', () => socket.destroy())
      socket.on('error', () => upstream.destroy())

      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head.length > 0) {
        upstream.write(head)
      }
      upstream.pipe(socket)
      socket.pipe(upstream)
    } catch {
      socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
    }
  })

  server.on('request', async (req, res) => {
    try {
      const url = new URL(req.url)
      const host = normalizeHost(url.hostname)
      const port = url.port
        ? Number(url.port)
        : url.protocol === 'https:'
          ? 443
          : 80

      if (!(await filter(host, port))) {
        res.writeHead(403, { 'content-type': 'text/plain' })
        res.end('Connection blocked by network allowlist')
        return
      }

      const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest
      const proxyReq = requestFn(
        {
          hostname: host,
          port,
          method: req.method,
          path: `${url.pathname}${url.search}`,
          headers: {
            ...stripHopByHop(req.headers),
            host: url.host,
          },
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 502, stripHopByHop(proxyRes.headers))
          proxyRes.pipe(res)
        },
      )

      proxyReq.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain' })
          res.end('Bad Gateway')
        } else {
          res.destroy()
        }
      })

      req.pipe(proxyReq)
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain' })
      res.end('Bad Request')
    }
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })

  const address = server.address()
  if (!address || typeof address === 'string') {
    throw new Error('failed to determine HTTP proxy port')
  }

  return {
    port: address.port,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
      }),
  }
}

const parseSocksRequest = (buffer) => {
  if (buffer.length < 4) return null
  if (buffer[0] !== 0x05) {
    return { error: true, consumed: buffer.length }
  }

  const atyp = buffer[3]
  let offset = 4
  let host = ''

  if (atyp === 0x01) {
    if (buffer.length < offset + 4 + 2) return null
    host = Array.from(buffer.subarray(offset, offset + 4)).join('.')
    offset += 4
  } else if (atyp === 0x03) {
    const size = buffer[offset]
    offset += 1
    if (buffer.length < offset + size + 2) return null
    host = buffer.subarray(offset, offset + size).toString('utf8')
    offset += size
  } else if (atyp === 0x04) {
    if (buffer.length < offset + 16 + 2) return null
    const parts = []
    for (let index = 0; index < 16; index += 2) {
      parts.push(buffer.readUInt16BE(offset + index).toString(16))
    }
    host = parts.join(':')
    offset += 16
  } else {
    return { error: true, consumed: buffer.length }
  }

  const port = buffer.readUInt16BE(offset)
  offset += 2
  return { host, port, consumed: offset }
}

const socksReply = (status) =>
  Buffer.from([0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

export const startSocksProxy = async ({ filter }) => {
  const server = createNetServer((socket) => {
    let stage = 'greeting'
    let buffer = Buffer.alloc(0)
    let upstream = null

    const fail = (status = 0x02) => {
      socket.end(socksReply(status))
    }

    socket.on('error', () => upstream?.destroy())

    socket.on('data', async (chunk) => {
      if (stage === 'stream') {
        upstream?.write(chunk)
        return
      }

      buffer = Buffer.concat([buffer, chunk])

      if (stage === 'greeting') {
        if (buffer.length < 2) return
        const methodCount = buffer[1]
        if (buffer.length < 2 + methodCount) return
        socket.write(Buffer.from([0x05, 0x00]))
        buffer = buffer.subarray(2 + methodCount)
        stage = 'request'
      }

      if (stage !== 'request') return

      const parsed = parseSocksRequest(buffer)
      if (!parsed) return
      if (parsed.error) {
        fail(0x07)
        return
      }

      stage = 'connecting'
      buffer = buffer.subarray(parsed.consumed)

      try {
        const host = normalizeHost(parsed.host)
        if (!(await filter(host, parsed.port))) {
          fail(0x02)
          return
        }

        upstream = await connectUpstream(parsed.host, parsed.port)
        upstream.on('error', () => socket.destroy())
        upstream.on('close', () => socket.destroy())
        socket.on('close', () => upstream.destroy())
        socket.write(socksReply(0x00))
        if (buffer.length > 0) {
          upstream.write(buffer)
          buffer = Buffer.alloc(0)
        }
        stage = 'stream'
        upstream.pipe(socket)
      } catch {
        fail(0x04)
      }
    })
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })

  const address = server.address()
  if (!address || typeof address === 'string') {
    throw new Error('failed to determine SOCKS proxy port')
  }

  return {
    port: address.port,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
      }),
  }
}
