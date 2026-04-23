import path from 'node:path'
import crypto from 'node:crypto'
import http from 'node:http'
import net from 'node:net'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'

const proxyEnvNames = [
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'ALL_PROXY',
  'https_proxy',
  'http_proxy',
  'all_proxy',
]

const hasProxyEnv = proxyEnvNames.some((name) => process.env[name])

const candidateRoots = [
  process.cwd(),
  process.env.GUARD_CWD,
  process.env.GUARD_PROJECT_DIR,
].filter((value, index, values) => value && values.indexOf(value) === index)

const resolveFromProject = (specifier) => {
  for (const root of candidateRoots) {
    try {
      const require = createRequire(path.join(root, 'package.json'))
      return require.resolve(specifier)
    } catch {}
  }
  return null
}

const selectHttpProxy = (url) => {
  const env =
    url.protocol === 'https:'
      ? process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy
      : process.env.HTTP_PROXY || process.env.http_proxy
  if (!env) return null
  try {
    const proxy = new URL(env)
    return proxy.protocol === 'http:' ? proxy : null
  } catch {
    return null
  }
}

const headersToObject = (headers) => {
  const out = {}
  if (!headers) return out
  const source = new Headers(headers)
  for (const [key, value] of source.entries()) {
    out[key] = value
  }
  return out
}

const installFetchFallback = () => {
  if (typeof globalThis.fetch !== 'function') return
  const nativeFetch = globalThis.fetch.bind(globalThis)

  globalThis.fetch = async (input, init = {}) => {
    const target = new URL(typeof input === 'string' || input instanceof URL ? input : input.url)
    const proxy = selectHttpProxy(target)
    if (!proxy || !['http:', 'https:'].includes(target.protocol)) {
      return nativeFetch(input, init)
    }
    if (target.protocol !== 'http:') {
      return nativeFetch(input, init)
    }

    const method = init.method || (typeof input === 'object' ? input.method : null) || 'GET'
    const headers = {
      ...headersToObject(typeof input === 'object' ? input.headers : null),
      ...headersToObject(init.headers),
    }
    const body = init.body

    return await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: proxy.hostname,
          port: Number(proxy.port || 80),
          method,
          path: target.href,
          headers,
        },
        (res) => {
          const chunks = []
          res.on('data', (chunk) => chunks.push(chunk))
          res.on('end', () => {
            resolve(
              new Response(Buffer.concat(chunks), {
                status: res.statusCode || 0,
                statusText: res.statusMessage || '',
                headers: res.headers,
              }),
            )
          })
        },
      )
      req.on('error', reject)
      if (body) {
        req.end(body)
      } else {
        req.end()
      }
    })
  }
}

const dispatch = (target, name, event) => {
  target.dispatchEvent(event)
  const handler = target[`on${name}`]
  if (typeof handler === 'function') {
    handler.call(target, event)
  }
}

const makeErrorEvent = (error) =>
  typeof ErrorEvent === 'function'
    ? new ErrorEvent('error', { error, message: error.message })
    : new Event('error')

const makeCloseEvent = () =>
  typeof CloseEvent === 'function' ? new CloseEvent('close') : new Event('close')

const installWebSocketFallback = () => {
  if (typeof globalThis.WebSocket !== 'function') return
  const NativeWebSocket = globalThis.WebSocket

  class GuardProxyWebSocket extends EventTarget {
    static CONNECTING = 0
    static OPEN = 1
    static CLOSING = 2
    static CLOSED = 3

    constructor(url, protocols) {
      super()
      const target = new URL(url)
      const proxy = selectHttpProxy(new URL(`http://${target.host}`))
      if (!proxy || target.protocol !== 'ws:') {
        return new NativeWebSocket(url, protocols)
      }

      this.url = target.href
      this.protocol = ''
      this.extensions = ''
      this.readyState = GuardProxyWebSocket.CONNECTING
      this.bufferedAmount = 0
      this.binaryType = 'blob'
      this._socket = null
      this._connect(target, proxy, protocols).catch((error) => {
        this.readyState = GuardProxyWebSocket.CLOSED
        dispatch(this, 'error', makeErrorEvent(error))
        dispatch(this, 'close', makeCloseEvent())
      })
    }

    async _connect(target, proxy, protocols) {
      const socket = net.connect({
        host: proxy.hostname,
        port: Number(proxy.port || 80),
      })
      this._socket = socket

      await new Promise((resolve, reject) => {
        socket.once('connect', resolve)
        socket.once('error', reject)
      })

      const key = crypto.randomBytes(16).toString('base64')
      const headers = [
        `GET ${target.href} HTTP/1.1`,
        `Host: ${target.host}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${key}`,
        'Sec-WebSocket-Version: 13',
      ]
      if (Array.isArray(protocols) && protocols.length > 0) {
        headers.push(`Sec-WebSocket-Protocol: ${protocols.join(', ')}`)
      } else if (typeof protocols === 'string' && protocols) {
        headers.push(`Sec-WebSocket-Protocol: ${protocols}`)
      }
      socket.write(`${headers.join('\r\n')}\r\n\r\n`)

      let buffer = Buffer.alloc(0)
      await new Promise((resolve, reject) => {
        const onData = (chunk) => {
          buffer = Buffer.concat([buffer, chunk])
          const headerEnd = buffer.indexOf('\r\n\r\n')
          if (headerEnd === -1) return
          socket.off('data', onData)
          const header = buffer.subarray(0, headerEnd).toString('utf8')
          if (!/^HTTP\/1\.[01] 101\b/.test(header)) {
            reject(new Error(`WebSocket proxy handshake failed: ${header.split('\r\n')[0]}`))
            return
          }
          resolve()
        }
        socket.on('data', onData)
        socket.once('error', reject)
      })

      this.readyState = GuardProxyWebSocket.OPEN
      dispatch(this, 'open', new Event('open'))
      socket.once('close', () => {
        this.readyState = GuardProxyWebSocket.CLOSED
        dispatch(this, 'close', makeCloseEvent())
      })
    }

    send() {
      if (this.readyState !== GuardProxyWebSocket.OPEN) {
        throw new Error('WebSocket is not open')
      }
    }

    close() {
      if (this.readyState >= GuardProxyWebSocket.CLOSING) return
      this.readyState = GuardProxyWebSocket.CLOSING
      this._socket?.end()
    }
  }

  globalThis.WebSocket = GuardProxyWebSocket
}

if (hasProxyEnv) {
  let installedUndici = false
  try {
    const undiciPath = resolveFromProject('undici')
    if (undiciPath) {
      const { EnvHttpProxyAgent, setGlobalDispatcher } = await import(
        pathToFileURL(undiciPath).href
      )
      if (EnvHttpProxyAgent && setGlobalDispatcher) {
        setGlobalDispatcher(new EnvHttpProxyAgent())
        installedUndici = true
      }
    }
  } catch {}
  if (!installedUndici) {
    installFetchFallback()
    installWebSocketFallback()
  }
}
