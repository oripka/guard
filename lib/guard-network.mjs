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

const durationToExpiresAt = (duration) => {
  const value = String(duration || 'run').toLowerCase()
  if (value === 'forever' || value === 'run' || value === 'session') return 0
  const match = /^(\d+)(s|m|h|d)$/.exec(value)
  if (!match) return 0
  const amount = Number(match[1])
  const unitMs = match[2] === 's' ? 1_000 : match[2] === 'm' ? 60_000 : match[2] === 'h' ? 3_600_000 : 86_400_000
  return Date.now() + amount * unitMs
}

const cachedDecisionActive = (cache, host) => {
  const entry = cache.get(host)
  if (!entry) return false
  if (entry.expiresAt && entry.expiresAt <= Date.now()) {
    cache.delete(host)
    return false
  }
  return true
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

const upstreamErrorMessage = (host, port, error) => {
  const code = error?.code ? `${error.code}: ` : ''
  return `Upstream connection failed for ${host}:${port} after policy allow. ${code}${error?.message || 'unknown error'}`
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
  const allowedHosts = new Map()
  const deniedHosts = new Map()
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

    const decisionKey = `${normalizedHost}:${Number.isInteger(port) ? port : ''}`

    if (cachedDecisionActive(deniedHosts, decisionKey)) {
      record({ host: normalizedHost, port, allowed: false, reason: 'cached-deny' })
      return false
    }
    if (cachedDecisionActive(allowedHosts, decisionKey)) {
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

    if (!pendingHosts.has(decisionKey)) {
      pendingHosts.set(
        decisionKey,
        Promise.resolve(options.ask(normalizedHost, port))
          .then((decision) => {
            const allow = typeof decision === 'object' && decision !== null
              ? decision.action === 'allow' || decision.allow === true
              : Boolean(decision)
            const expiresAt = typeof decision === 'object' && decision !== null
              ? durationToExpiresAt(decision.duration)
              : 0
            if (allow) {
              allowedHosts.set(decisionKey, { expiresAt })
            } else {
              deniedHosts.set(decisionKey, { expiresAt })
            }
            record({
              host: normalizedHost,
              port,
              allowed: allow,
              reason: allow ? 'ask-allow' : 'ask-deny',
              duration: typeof decision === 'object' && decision !== null ? decision.duration || 'run' : 'run',
            })
            return allow
          })
          .finally(() => {
            pendingHosts.delete(decisionKey)
          }),
      )
    }

    return pendingHosts.get(decisionKey)
  }
}

export const buildProxyEnv = ({ httpPort, socksPort, host = 'localhost', caCertPath = '', caDir = '' } = {}) => {
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
    entries.push(`NPM_CONFIG_PROXY=${value}`)
    entries.push(`NPM_CONFIG_HTTP_PROXY=${value}`)
    entries.push(`NPM_CONFIG_HTTPS_PROXY=${value}`)
    entries.push(`npm_config_proxy=${value}`)
    entries.push(`npm_config_http_proxy=${value}`)
    entries.push(`npm_config_https_proxy=${value}`)
    entries.push(`YARN_HTTP_PROXY=${value}`)
    entries.push(`YARN_HTTPS_PROXY=${value}`)
    entries.push(`CARGO_HTTP_PROXY=${value}`)
    entries.push(`DOCKER_HTTP_PROXY=${value}`)
    entries.push(`DOCKER_HTTPS_PROXY=${value}`)
    entries.push(`CLOUDSDK_PROXY_TYPE=http`)
    entries.push(`CLOUDSDK_PROXY_ADDRESS=${host}`)
    entries.push(`CLOUDSDK_PROXY_PORT=${httpPort}`)
  }

  if (caCertPath) {
    entries.push(`SSL_CERT_FILE=${caCertPath}`)
    entries.push(`NODE_EXTRA_CA_CERTS=${caCertPath}`)
    entries.push(`YARN_HTTPS_CA_FILE_PATH=${caCertPath}`)
    entries.push(`PIP_CERT=${caCertPath}`)
    entries.push(`CARGO_HTTP_CAINFO=${caCertPath}`)
    entries.push(`GIT_SSL_CAINFO=${caCertPath}`)
    entries.push(`GIT_PROXY_SSL_CAINFO=${caCertPath}`)
  }

  if (caDir) {
    entries.push(`SSL_CERT_DIR=${caDir}`)
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

const decodePathPart = (value) => {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

const stripArchiveSuffix = (filename) => {
  const suffixes = ['.tar.gz', '.tgz', '.crate', '.whl', '.zip']
  for (const suffix of suffixes) {
    if (filename.endsWith(suffix)) {
      return filename.slice(0, -suffix.length)
    }
  }
  return ''
}

const splitNameVersion = (base, packageName) => {
  if (!base || !packageName) return null
  const normalizedPackage = packageName.split('/').pop()
  const prefix = `${normalizedPackage}-`
  if (!base.startsWith(prefix)) return null
  const version = base.slice(prefix.length)
  return version ? { name: packageName, version } : null
}

const parseNdjson = (body) =>
  String(body || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line))

const parseNpmPackageFetch = (pathname) => {
  const parts = pathname.split('/').filter(Boolean).map(decodePathPart)
  const dashIndex = parts.indexOf('-')
  if (dashIndex < 1 || dashIndex !== parts.length - 2) return null
  const filename = parts.at(-1)
  if (!filename?.endsWith('.tgz')) return null

  const packageName = parts.slice(0, dashIndex).join('/')
  const base = stripArchiveSuffix(filename)
  return splitNameVersion(base, packageName)
}

const parsePypiPackageFetch = (pathname) => {
  const filename = decodePathPart(pathname.split('/').filter(Boolean).at(-1) || '')
  const base = stripArchiveSuffix(filename)
  if (!base) return null

  if (filename.endsWith('.whl')) {
    const [name, version] = base.split('-')
    return name && version ? { name, version } : null
  }

  const match = /^(.+)-([0-9][A-Za-z0-9.!+_-]*)$/.exec(base)
  if (!match) return null
  return { name: match[1], version: match[2] }
}

const parseCratesPackageFetch = (pathname) => {
  const parts = pathname.split('/').filter(Boolean).map(decodePathPart)
  if (parts.length !== 3 || parts[0] !== 'crates') return null
  const [packageName, filename] = [parts[1], parts[2]]
  if (!filename.endsWith('.crate')) return null
  const base = stripArchiveSuffix(filename)
  return splitNameVersion(base, packageName)
}

export const detectPackageFetch = ({ host, method = 'GET', path = '' } = {}) => {
  const normalizedHost = normalizeHost(host)
  const normalizedMethod = String(method || 'GET').toUpperCase()
  if (!['GET', 'HEAD'].includes(normalizedMethod)) return null

  let pathname = ''
  try {
    pathname = new URL(path || '/', 'http://guard.local').pathname
  } catch {
    pathname = String(path || '').split('?')[0]
  }

  const registry = normalizedHost === 'registry.npmjs.org'
    ? { type: 'npm', parser: parseNpmPackageFetch }
    : normalizedHost === 'files.pythonhosted.org'
      ? { type: 'pypi', parser: parsePypiPackageFetch }
      : normalizedHost === 'static.crates.io'
        ? { type: 'cargo', parser: parseCratesPackageFetch }
        : null
  if (!registry) return null

  const parsed = registry.parser(pathname)
  if (!parsed) return null
  return {
    ecosystem: registry.type,
    registryHost: normalizedHost,
    name: parsed.name,
    version: parsed.version,
    purl: `pkg:${registry.type}/${parsed.name}@${parsed.version}`,
  }
}

export const createSocketFreePackageLookup = ({
  fetchImpl = globalThis.fetch,
  endpointBase = 'https://firewall-api.socket.dev/purl/',
  ttlMs = 60 * 60 * 1000,
  timeoutMs = 5000,
  now = () => Date.now(),
} = {}) => {
  if (typeof fetchImpl !== 'function') {
    throw new Error('Socket package lookup requires fetch support')
  }
  const cache = new Map()
  const ttl = Math.max(1, Number(ttlMs) || 60 * 60 * 1000)
  const timeout = Math.max(1, Number(timeoutMs) || 5000)

  return async (packageFetch) => {
    const purl = String(packageFetch?.purl || '')
    if (!purl) {
      return { provider: 'socket-free', status: 'skipped', reason: 'missing-purl' }
    }

    const currentTime = now()
    const cached = cache.get(purl)
    if (cached && cached.expiresAt > currentTime) {
      const value = await cached.promise
      return { ...value, cached: true }
    }
    if (cached) {
      cache.delete(purl)
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)
    const promise = (async () => {
      try {
        const response = await fetchImpl(`${endpointBase}${encodeURIComponent(purl)}`, {
          method: 'GET',
          signal: controller.signal,
          headers: {
            accept: 'application/x-ndjson, application/json, text/plain',
          },
        })
        const body = await response.text()
        if (!response.ok) {
          return {
            provider: 'socket-free',
            status: 'error',
            cached: false,
            statusCode: response.status,
            alerts: [],
            message: body.slice(0, 500),
          }
        }
        return {
          provider: 'socket-free',
          status: 'ok',
          cached: false,
          statusCode: response.status,
          alerts: parseNdjson(body),
        }
      } catch (error) {
        return {
          provider: 'socket-free',
          status: 'error',
          cached: false,
          alerts: [],
          message: error?.name === 'AbortError' ? 'lookup timed out' : error?.message || String(error),
        }
      } finally {
        clearTimeout(timer)
      }
    })()

    cache.set(purl, {
      expiresAt: currentTime + ttl,
      promise,
    })
    return promise
  }
}

export const startHttpProxy = async ({
  filter,
  tlsIntercept = false,
  tlsCertificateIssuer = null,
  upstreamTls = {},
  requestFilter = null,
  onTraffic = null,
  packageFetchDetector = detectPackageFetch,
  packageFetchLookup = null,
  packagePolicy = null,
  listenHost = '127.0.0.1',
} = {}) => {
  const recordTraffic = (event) => {
    if (typeof onTraffic === 'function') {
      onTraffic(event)
    }
  }

  const recordPackageFetch = async ({ protocol, transport, host, port, method, path }) => {
    const packageFetch = typeof packageFetchDetector === 'function'
      ? packageFetchDetector({ host, method, path })
      : null
    if (!packageFetch) return
    const lookup = typeof packageFetchLookup === 'function'
      ? await packageFetchLookup(packageFetch)
      : undefined
    recordTraffic({
      phase: 'package-fetch',
      protocol,
      transport,
      host,
      port,
      method,
      path,
      package: packageFetch,
      ...(lookup ? { packageLookup: lookup } : {}),
    })
    return { packageFetch, packageLookup: lookup }
  }

  const packageBlockBody = (packageFetch, decision = {}) => [
    `Guard blocked package download: ${packageFetch.purl || `${packageFetch.ecosystem}/${packageFetch.name}@${packageFetch.version}`}`,
    decision.summary || decision.reason || 'Package blocked by supply-chain policy',
    decision.referenceUrl ? `Reference: ${decision.referenceUrl}` : '',
    '',
  ].filter(Boolean).join('\n')

  const applyPackageRequestPolicy = async ({ protocol, transport, host, port, method, path, headers }) => {
    const upstreamHeaders = { ...stripHopByHop(headers) }
    const recorded = await recordPackageFetch({
      protocol,
      transport,
      host,
      port,
      method,
      path,
    })
    const packageFetch = recorded?.packageFetch
    if (packageFetch && typeof packagePolicy?.evaluatePackageFetch === 'function') {
      const decision = await packagePolicy.evaluatePackageFetch(packageFetch, {
        packageLookup: recorded?.packageLookup || null,
        request: { protocol, transport, host, port, method, path },
      })
      if (decision?.allowed === false) {
        recordTraffic({
          phase: 'package-blocked',
          protocol,
          transport,
          host,
          port,
          method,
          path,
          package: packageFetch,
          reason: decision.reason || 'package-policy',
          summary: decision.summary || '',
          referenceUrl: decision.referenceUrl || '',
        })
        return { blocked: true, packageFetch, decision, headers: upstreamHeaders }
      }
    }
    const metadataPolicy = typeof packagePolicy?.prepareMetadataRequest === 'function'
      ? packagePolicy.prepareMetadataRequest({ host, method, path, headers: upstreamHeaders })
      : null
    return {
      blocked: false,
      headers: upstreamHeaders,
      responsePolicy: metadataPolicy?.responsePolicy || null,
    }
  }

  const writePackageBlock = (res, packageFetch, decision) => {
    const body = packageBlockBody(packageFetch, decision)
    res.writeHead(403, {
      'content-type': 'text/plain',
      'content-length': Buffer.byteLength(body),
    })
    res.end(body)
  }

  const handleProxyResponse = ({ proxyRes, res, responsePolicy, onData, onEnd }) => {
    if (!responsePolicy || typeof packagePolicy?.filterMetadataResponse !== 'function') {
      res.writeHead(proxyRes.statusCode || 502, stripHopByHop(proxyRes.headers))
      proxyRes.on('data', onData)
      proxyRes.on('end', onEnd)
      proxyRes.pipe(res)
      return
    }

    const chunks = []
    proxyRes.on('data', (chunk) => {
      chunks.push(chunk)
      onData(chunk)
    })
    proxyRes.on('end', async () => {
      try {
        const body = Buffer.concat(chunks)
        const filtered = await packagePolicy.filterMetadataResponse({
          responsePolicy,
          statusCode: proxyRes.statusCode || 0,
          headers: proxyRes.headers,
          body,
        })
        const output = Buffer.isBuffer(filtered?.body)
          ? filtered.body
          : Buffer.from(String(filtered?.body ?? body))
        const headers = {
          ...stripHopByHop(filtered?.headers || proxyRes.headers),
          'content-length': String(output.length),
        }
        res.writeHead(proxyRes.statusCode || 502, headers)
        res.end(output)
      } catch {
        res.writeHead(proxyRes.statusCode || 502, stripHopByHop(proxyRes.headers))
        res.end(Buffer.concat(chunks))
      } finally {
        onEnd()
      }
    })
  }

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

      let bytesSent = 0
      let bytesReceived = 0
      req.on('data', (chunk) => {
        bytesSent += chunk.length
      })
      recordTraffic({
        phase: 'started',
        protocol: 'https',
        transport: 'http-proxy',
        host: target.host,
        port: target.port,
        method: req.method || 'GET',
        path: requestPath,
      })
      const packageRequest = await applyPackageRequestPolicy({
        protocol: 'https',
        transport: 'http-proxy',
        host: target.host,
        port: target.port,
        method: req.method || 'GET',
        path: requestPath,
        headers: req.headers,
      })
      if (packageRequest.blocked) {
        writePackageBlock(res, packageRequest.packageFetch, packageRequest.decision)
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
            ...packageRequest.headers,
            host: req.headers.host || `${target.host}:${target.port}`,
          },
        },
        (proxyRes) => {
          handleProxyResponse({
            proxyRes,
            res,
            responsePolicy: packageRequest.responsePolicy,
            onData: (chunk) => {
              bytesReceived += chunk.length
            },
            onEnd: () => {
              recordTraffic({
                phase: 'closed',
                protocol: 'https',
                transport: 'http-proxy',
                host: target.host,
                port: target.port,
                method: req.method || 'GET',
                path: requestPath,
                statusCode: proxyRes.statusCode || 0,
                bytesSent,
                bytesReceived,
              })
            },
          })
        },
      )

      proxyReq.on('error', () => {
        recordTraffic({
          phase: 'closed',
          protocol: 'https',
          transport: 'http-proxy',
          host: target.host,
          port: target.port,
          method: req.method || 'GET',
          path: requestPath,
          status: 'error',
          bytesSent,
          bytesReceived,
        })
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
    let host = req.url || 'unknown'
    let port = 0
    try {
      const url = new URL(req.url)
      host = normalizeHost(url.hostname)
      port = url.port ? Number(url.port) : url.protocol === 'wss:' ? 443 : 80

      if (!(await filter(host, port))) {
        socket.end(
          'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nConnection blocked by network allowlist',
        )
        return
      }

      const upstream = await connectUpstream(host, port)
      upstream.on('error', () => socket.destroy())
      socket.on('error', () => upstream.destroy())
      let bytesSent = head.length
      let bytesReceived = 0
      recordTraffic({
        phase: 'started',
        protocol: url.protocol.replace(':', '') || 'ws',
        transport: 'http-upgrade',
        host,
        port,
        method: req.method || 'GET',
        path: `${url.pathname}${url.search}`,
      })
      socket.on('data', (chunk) => {
        bytesSent += chunk.length
      })
      upstream.on('data', (chunk) => {
        bytesReceived += chunk.length
      })
      socket.on('close', () => {
        recordTraffic({
          phase: 'closed',
          protocol: url.protocol.replace(':', '') || 'ws',
          transport: 'http-upgrade',
          host,
          port,
          method: req.method || 'GET',
          path: `${url.pathname}${url.search}`,
          bytesSent,
          bytesReceived,
        })
      })

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
    } catch (error) {
      socket.end(`HTTP/1.1 502 Upstream Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${upstreamErrorMessage(host, port, error)}`)
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
      let bytesSent = head.length
      let bytesReceived = 0
      recordTraffic({
        phase: 'started',
        protocol: target.port === 443 ? 'https' : 'tcp',
        transport: 'connect',
        host: target.host,
        port: target.port,
      })
      socket.on('data', (chunk) => {
        bytesSent += chunk.length
      })
      upstream.on('data', (chunk) => {
        bytesReceived += chunk.length
      })
      socket.on('close', () => {
        recordTraffic({
          phase: 'closed',
          protocol: target.port === 443 ? 'https' : 'tcp',
          transport: 'connect',
          host: target.host,
          port: target.port,
          bytesSent,
          bytesReceived,
        })
      })

      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head.length > 0) {
        upstream.write(head)
      }
      upstream.pipe(socket)
      socket.pipe(upstream)
    } catch (error) {
      const target = parseConnectTarget(req.url || '')
      const host = target?.host || req.url || 'unknown'
      const port = target?.port || 0
      socket.end(`HTTP/1.1 502 Upstream Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${upstreamErrorMessage(host, port, error)}`)
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

      let bytesSent = 0
      let bytesReceived = 0
      req.on('data', (chunk) => {
        bytesSent += chunk.length
      })
      recordTraffic({
        phase: 'started',
        protocol: url.protocol.replace(':', '') || 'http',
        transport: 'http-proxy',
        host,
        port,
        method: req.method || 'GET',
        path: `${url.pathname}${url.search}`,
      })
      const requestPath = `${url.pathname}${url.search}`
      const packageRequest = await applyPackageRequestPolicy({
        protocol: url.protocol.replace(':', '') || 'http',
        transport: 'http-proxy',
        host,
        port,
        method: req.method || 'GET',
        path: requestPath,
        headers: req.headers,
      })
      if (packageRequest.blocked) {
        writePackageBlock(res, packageRequest.packageFetch, packageRequest.decision)
        return
      }
      const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest
      const proxyReq = requestFn(
        {
          hostname: host,
          port,
          method: req.method,
          path: requestPath,
          headers: {
            ...packageRequest.headers,
            host: url.host,
          },
        },
        (proxyRes) => {
          handleProxyResponse({
            proxyRes,
            res,
            responsePolicy: packageRequest.responsePolicy,
            onData: (chunk) => {
              bytesReceived += chunk.length
            },
            onEnd: () => {
              recordTraffic({
                phase: 'closed',
                protocol: url.protocol.replace(':', '') || 'http',
                transport: 'http-proxy',
                host,
                port,
                method: req.method || 'GET',
                path: requestPath,
                statusCode: proxyRes.statusCode || 0,
                bytesSent,
                bytesReceived,
              })
            },
          })
        },
      )

      proxyReq.on('error', () => {
        recordTraffic({
          phase: 'closed',
          protocol: url.protocol.replace(':', '') || 'http',
          transport: 'http-proxy',
          host,
          port,
          method: req.method || 'GET',
          path: requestPath,
          status: 'error',
          bytesSent,
          bytesReceived,
        })
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
    server.listen(0, listenHost, resolve)
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

export const startSocksProxy = async ({ filter, onTraffic = null, listenHost = '127.0.0.1' }) => {
  const recordTraffic = (event) => {
    if (typeof onTraffic === 'function') {
      onTraffic(event)
    }
  }

  const server = createNetServer((socket) => {
    let stage = 'greeting'
    let buffer = Buffer.alloc(0)
    let upstream = null
    let flow = null

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
        flow = {
          protocol: parsed.port === 443 ? 'https' : 'tcp',
          transport: 'socks',
          host,
          port: parsed.port,
          bytesSent: buffer.length,
          bytesReceived: 0,
        }
        recordTraffic({
          phase: 'started',
          protocol: flow.protocol,
          transport: flow.transport,
          host: flow.host,
          port: flow.port,
        })
        socket.on('data', (chunk) => {
          if (stage === 'stream') flow.bytesSent += chunk.length
        })
        upstream.on('data', (chunk) => {
          flow.bytesReceived += chunk.length
        })
        socket.on('close', () => {
          recordTraffic({
            phase: 'closed',
            protocol: flow.protocol,
            transport: flow.transport,
            host: flow.host,
            port: flow.port,
            bytesSent: flow.bytesSent,
            bytesReceived: flow.bytesReceived,
          })
        })
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
    server.listen(0, listenHost, resolve)
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
