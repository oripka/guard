const DAY_MS = 24 * 60 * 60 * 1000

const asArray = (value) => (Array.isArray(value) ? value : [])

const normalizeHost = (value) => {
  if (typeof value !== 'string') return ''
  let host = value.trim().toLowerCase()
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1)
  if (host.endsWith('.')) host = host.slice(0, -1)
  return host
}

const decodePathPart = (value) => {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

const stripArchiveSuffix = (filename = '') => {
  const suffixes = ['.tar.gz', '.tgz', '.crate', '.whl', '.zip']
  for (const suffix of suffixes) {
    if (filename.endsWith(suffix)) return filename.slice(0, -suffix.length)
  }
  return ''
}

const normalizePackageName = (ecosystem, name) => {
  const value = String(name || '').trim()
  if (ecosystem === 'npm') return value.toLowerCase()
  if (ecosystem === 'pypi') return value.toLowerCase().replace(/[-_.]+/g, '-')
  return value.toLowerCase()
}

export const packagePurl = ({ ecosystem, name, version }) => {
  const normalizedEcosystem = String(ecosystem || '').trim().toLowerCase()
  const normalizedName = normalizePackageName(normalizedEcosystem, name)
  const normalizedVersion = String(version || '').trim()
  return normalizedEcosystem && normalizedName && normalizedVersion
    ? `pkg:${normalizedEcosystem}/${normalizedName}@${normalizedVersion}`
    : ''
}

const normalizePurl = (value) => {
  const text = String(value || '').trim()
  const match = /^pkg:([^/]+)\/(.+?)@([^@]+)$/.exec(text)
  if (!match) return text.toLowerCase()
  return packagePurl({
    ecosystem: match[1],
    name: match[2],
    version: match[3],
  })
}

const packageKeys = (pkg = {}) => {
  const purl = packagePurl(pkg)
  const base = [
    purl,
    `${String(pkg.ecosystem || '').toLowerCase()}/${normalizePackageName(pkg.ecosystem, pkg.name)}@${String(pkg.version || '').trim()}`,
    `${normalizePackageName(pkg.ecosystem, pkg.name)}@${String(pkg.version || '').trim()}`,
  ].filter(Boolean)
  return new Set(base.map((value) => value.toLowerCase()))
}

const normalizeHeaderBag = (headers = {}) => {
  const out = {}
  for (const [key, value] of Object.entries(headers || {})) {
    out[String(key).toLowerCase()] = value
  }
  return out
}

const deleteHeader = (headers, name) => {
  const lower = name.toLowerCase()
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === lower) delete headers[key]
  }
}

const setHeader = (headers, name, value) => {
  deleteHeader(headers, name)
  headers[name] = value
}

const parseRequestPath = (path = '') => {
  try {
    return new URL(path || '/', 'http://guard.local').pathname
  } catch {
    return String(path || '').split('?')[0]
  }
}

const parseNpmMetadataRequest = (pathname) => {
  const parts = pathname.split('/').filter(Boolean).map(decodePathPart)
  if (parts.length < 1 || parts.includes('-')) return null
  const packageName = parts[0].startsWith('@') && parts.length >= 2
    ? `${parts[0]}/${parts[1]}`
    : parts[0]
  return packageName ? { ecosystem: 'npm', name: packageName } : null
}

const parsePypiMetadataRequest = (pathname) => {
  const parts = pathname.split('/').filter(Boolean).map(decodePathPart)
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'simple') return null
  return parts[1] ? { ecosystem: 'pypi', name: parts[1] } : null
}

export const detectPackageMetadataRequest = ({ host, method = 'GET', path = '' } = {}) => {
  const normalizedHost = normalizeHost(host)
  const normalizedMethod = String(method || 'GET').toUpperCase()
  if (!['GET', 'HEAD'].includes(normalizedMethod)) return null
  const pathname = parseRequestPath(path)
  if (normalizedHost === 'registry.npmjs.org') {
    return parseNpmMetadataRequest(pathname)
  }
  if (normalizedHost === 'pypi.org') {
    return parsePypiMetadataRequest(pathname)
  }
  return null
}

const parseDate = (value) => {
  const ms = Date.parse(String(value || ''))
  return Number.isFinite(ms) ? new Date(ms) : null
}

export const cooldownIsWithinWindow = (publishDate, cooldownDays, now = new Date()) => {
  const date = publishDate instanceof Date ? publishDate : parseDate(publishDate)
  const days = Number(cooldownDays)
  if (!date || !Number.isFinite(days) || days <= 0) {
    return { withinCooldown: false, daysSincePublish: 0, daysRemaining: 0 }
  }
  const elapsed = Math.max(0, Number(now) - Number(date))
  const daysSincePublish = Math.floor(elapsed / DAY_MS)
  const daysRemaining = Math.max(0, days - daysSincePublish)
  return {
    withinCooldown: daysSincePublish < days,
    daysSincePublish,
    daysRemaining,
  }
}

const latestEligibleVersion = (dates, tooNew) => {
  let latest = ''
  let latestTime = 0
  for (const [version, date] of dates) {
    if (tooNew.has(version)) continue
    const time = Number(date)
    if (time > latestTime) {
      latest = version
      latestTime = time
    }
  }
  return latest
}

export const filterNpmMetadataForCooldown = (body, { days = 5, now = new Date(), packageName = '' } = {}) => {
  let metadata
  try {
    metadata = JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') : String(body || ''))
  } catch {
    return { modified: false, body, stripped: 0, remaining: 0, reason: 'invalid-npm-metadata' }
  }
  const time = metadata?.time && typeof metadata.time === 'object' ? metadata.time : {}
  const dates = new Map()
  for (const [version, value] of Object.entries(time)) {
    if (version === 'created' || version === 'modified') continue
    const date = parseDate(value)
    if (date) dates.set(version, date)
  }
  const tooNew = new Set()
  const strippedVersions = []
  for (const [version, date] of dates) {
    const cooldown = cooldownIsWithinWindow(date, days, now)
    if (cooldown.withinCooldown) {
      tooNew.add(version)
      strippedVersions.push({
        version,
        publishDate: date.toISOString(),
        daysSincePublish: cooldown.daysSincePublish,
        daysRemaining: cooldown.daysRemaining,
      })
    }
  }
  if (tooNew.size === 0) {
    return { modified: false, body, stripped: 0, remaining: dates.size }
  }

  if (metadata.versions && typeof metadata.versions === 'object') {
    for (const version of tooNew) delete metadata.versions[version]
  }
  if (metadata.time && typeof metadata.time === 'object') {
    for (const version of tooNew) delete metadata.time[version]
  }
  if (metadata['dist-tags'] && typeof metadata['dist-tags'] === 'object') {
    const replacement = latestEligibleVersion(dates, tooNew)
    for (const [tag, version] of Object.entries(metadata['dist-tags'])) {
      if (tooNew.has(version)) {
        if (replacement) metadata['dist-tags'][tag] = replacement
        else delete metadata['dist-tags'][tag]
      }
    }
  }

  return {
    modified: true,
    body: Buffer.from(`${JSON.stringify(metadata)}\n`),
    stripped: tooNew.size,
    remaining: Math.max(0, dates.size - tooNew.size),
    package: { ecosystem: 'npm', name: packageName },
    strippedVersions,
  }
}

const versionFromPypiFilename = (filename = '') => {
  const base = stripArchiveSuffix(filename)
  if (!base) return ''
  if (filename.endsWith('.whl')) {
    const parts = base.split('-')
    return parts[1] || ''
  }
  const match = /^.+-([0-9][A-Za-z0-9.!+_-]*)$/.exec(base)
  return match?.[1] || ''
}

export const filterPypiSimpleMetadataForCooldown = (body, { days = 5, now = new Date(), packageName = '' } = {}) => {
  let metadata
  try {
    metadata = JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') : String(body || ''))
  } catch {
    return { modified: false, body, stripped: 0, remaining: 0, reason: 'invalid-pypi-metadata' }
  }
  if (!Array.isArray(metadata?.files)) {
    return { modified: false, body, stripped: 0, remaining: 0, reason: 'missing-pypi-files' }
  }

  const dates = new Map()
  for (const file of metadata.files) {
    const version = versionFromPypiFilename(String(file?.filename || ''))
    const date = parseDate(file?.['upload-time'])
    if (!version || !date) continue
    const existing = dates.get(version)
    if (!existing || date < existing) dates.set(version, date)
  }

  const tooNew = new Set()
  const strippedVersions = []
  for (const [version, date] of dates) {
    const cooldown = cooldownIsWithinWindow(date, days, now)
    if (cooldown.withinCooldown) {
      tooNew.add(version)
      strippedVersions.push({
        version,
        publishDate: date.toISOString(),
        daysSincePublish: cooldown.daysSincePublish,
        daysRemaining: cooldown.daysRemaining,
      })
    }
  }
  if (tooNew.size === 0) {
    return { modified: false, body, stripped: 0, remaining: dates.size }
  }

  metadata.files = metadata.files.filter((file) => {
    const version = versionFromPypiFilename(String(file?.filename || ''))
    return !version || !tooNew.has(version)
  })

  return {
    modified: true,
    body: Buffer.from(`${JSON.stringify(metadata)}\n`),
    stripped: tooNew.size,
    remaining: Math.max(0, dates.size - tooNew.size),
    package: { ecosystem: 'pypi', name: packageName },
    strippedVersions,
  }
}

const normalizeThreatIntelConfig = (config = {}) => {
  const raw = config && typeof config === 'object' ? config : {}
  const blocked = [
    ...asArray(raw.blockedPackages),
    ...asArray(raw.blockedPurls),
    ...asArray(raw.deniedPackages),
    ...asArray(raw.maliciousPackages),
  ].map(normalizePurl)
  const blockPackageLookupAlerts = raw.blockPackageLookupAlerts === true ||
    raw.blockOnPackageLookupAlerts === true ||
    raw.blockSocketAlerts === true
  return {
    enabled: raw.enabled === true || blocked.length > 0 || blockPackageLookupAlerts,
    endpoint: typeof raw.endpoint === 'string' ? raw.endpoint.trim() : '',
    apiKeyEnv: typeof raw.apiKeyEnv === 'string' ? raw.apiKeyEnv.trim() : '',
    failClosed: raw.failClosed === true,
    blockSuspicious: raw.blockSuspicious === true || raw.paranoid === true,
    blockPackageLookupAlerts,
    timeoutMs: Math.max(100, Number(raw.timeoutMs || 5000) || 5000),
    blocked,
  }
}

const normalizeCooldownConfig = (config = {}) => {
  const raw = config && typeof config === 'object'
    ? config
    : config === true
      ? { enabled: true }
      : {}
  return {
    enabled: raw.enabled === true,
    days: Math.max(0, Number(raw.days || 5) || 5),
    packagePublishedAt: raw.packagePublishedAt && typeof raw.packagePublishedAt === 'object'
      ? raw.packagePublishedAt
      : {},
  }
}

export const isPackagePolicyEnabled = (supplyChain = {}) => {
  const threat = normalizeThreatIntelConfig(supplyChain.threatIntelligence)
  const cooldown = normalizeCooldownConfig(supplyChain.dependencyCooldown)
  return threat.enabled || cooldown.enabled
}

const callThreatIntelEndpoint = async ({ endpoint, apiKeyEnv, timeoutMs, pkg, fetchImpl }) => {
  if (!endpoint || typeof fetchImpl !== 'function') return null
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const apiKey = apiKeyEnv ? process.env[apiKeyEnv] || '' : ''
    const response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
      },
      body: JSON.stringify(pkg),
      signal: controller.signal,
    })
    if (!response.ok) {
      throw new Error(`threat intelligence endpoint returned ${response.status}`)
    }
    return await response.json()
  } finally {
    clearTimeout(timeout)
  }
}

const blockingLookupAlert = (lookup = {}) => {
  if (!Array.isArray(lookup.alerts)) return null
  for (const alert of lookup.alerts) {
    if (!alert || typeof alert !== 'object') continue
    const values = [
      alert.action,
      alert.verdict,
      alert.status,
      alert.type,
      alert.severity,
      alert.risk,
    ].map((value) => String(value || '').trim().toLowerCase())
    if (values.some((value) => ['block', 'blocked', 'deny', 'denied', 'malicious', 'malware', 'critical'].includes(value))) {
      return alert
    }
  }
  return null
}

export const createPackagePolicy = ({
  supplyChain = {},
  now = () => new Date(),
  fetchImpl = globalThis.fetch,
  onEvent = null,
} = {}) => {
  const threat = normalizeThreatIntelConfig(supplyChain.threatIntelligence)
  const cooldown = normalizeCooldownConfig(supplyChain.dependencyCooldown)
  const blockedThreatKeys = new Set(threat.blocked.map((value) => value.toLowerCase()))
  const emit = (type, value = {}) => {
    if (typeof onEvent === 'function') onEvent(type, value)
  }

  const evaluateThreatIntel = async (pkg, { packageLookup = null } = {}) => {
    if (!threat.enabled) return null
    const keys = packageKeys(pkg)
    for (const key of keys) {
      if (blockedThreatKeys.has(key)) {
        return {
          allowed: false,
          reason: 'threat-intelligence',
          summary: 'Package matched a local threat-intelligence block rule',
          source: 'local-blocklist',
        }
      }
    }
    if (threat.blockPackageLookupAlerts && packageLookup) {
      const alert = blockingLookupAlert(packageLookup)
      if (alert) {
        return {
          allowed: false,
          reason: 'threat-intelligence',
          summary: alert.summary || alert.message || alert.title || 'Package lookup reported a blocking alert',
          referenceUrl: alert.referenceUrl || alert.referenceURL || alert.url || '',
          source: packageLookup.provider || 'package-lookup',
          data: alert,
        }
      }
    }
    if (!threat.endpoint) return null
    try {
      const result = await callThreatIntelEndpoint({
        endpoint: threat.endpoint,
        apiKeyEnv: threat.apiKeyEnv,
        timeoutMs: threat.timeoutMs,
        pkg,
        fetchImpl,
      })
      const action = String(result?.action || result?.verdict || '').toLowerCase()
      const malicious = result?.isMalware === true || result?.malicious === true
      const verified = result?.isVerified === true || result?.verified === true
      const suspicious = result?.suspicious === true || action === 'confirm'
      if (action === 'block' || action === 'deny' || verified || malicious || (suspicious && threat.blockSuspicious)) {
        return {
          allowed: false,
          reason: 'threat-intelligence',
          summary: result?.summary || 'Threat intelligence blocked this package',
          referenceUrl: result?.referenceUrl || result?.referenceURL || '',
          source: 'endpoint',
        }
      }
      emit('supply_chain.threat_intel.allowed', { package: pkg, result })
      return { allowed: true, reason: 'threat-intelligence', result }
    } catch (error) {
      emit('supply_chain.threat_intel.error', { package: pkg, error: error.message })
      if (threat.failClosed) {
        return {
          allowed: false,
          reason: 'threat-intelligence-unavailable',
          summary: error.message,
          source: 'endpoint',
        }
      }
      return null
    }
  }

  const evaluateCooldownFetch = (pkg) => {
    if (!cooldown.enabled) return null
    const publishedAt =
      cooldown.packagePublishedAt[pkg.purl] ||
      cooldown.packagePublishedAt[packagePurl(pkg)] ||
      cooldown.packagePublishedAt[`${pkg.ecosystem}/${normalizePackageName(pkg.ecosystem, pkg.name)}@${pkg.version}`] ||
      cooldown.packagePublishedAt[`${normalizePackageName(pkg.ecosystem, pkg.name)}@${pkg.version}`]
    if (!publishedAt) return null
    const result = cooldownIsWithinWindow(publishedAt, cooldown.days, now())
    if (!result.withinCooldown) return null
    return {
      allowed: false,
      reason: 'dependency-cooldown',
      summary: `Package version is inside the ${cooldown.days}-day dependency cooldown window`,
      cooldown: {
        days: cooldown.days,
        publishDate: new Date(publishedAt).toISOString(),
        daysSincePublish: result.daysSincePublish,
        daysRemaining: result.daysRemaining,
      },
    }
  }

  return {
    enabled: threat.enabled || cooldown.enabled,
    threat,
    cooldown,
    prepareMetadataRequest({ host, method, path, headers = {} } = {}) {
      if (!cooldown.enabled) return null
      const metadata = detectPackageMetadataRequest({ host, method, path })
      if (!metadata) return null
      if (metadata.ecosystem === 'npm') {
        setHeader(headers, 'accept', 'application/json')
      } else if (metadata.ecosystem === 'pypi') {
        setHeader(headers, 'accept', 'application/vnd.pypi.simple.v1+json')
      }
      setHeader(headers, 'accept-encoding', 'identity')
      deleteHeader(headers, 'if-none-match')
      deleteHeader(headers, 'if-modified-since')
      return {
        metadata,
        responsePolicy: {
          type: 'dependency-cooldown',
          ecosystem: metadata.ecosystem,
          name: metadata.name,
        },
      }
    },
    async filterMetadataResponse({ responsePolicy, statusCode, headers = {}, body } = {}) {
      if (!cooldown.enabled || responsePolicy?.type !== 'dependency-cooldown') {
        return { modified: false, body }
      }
      const filter = responsePolicy.ecosystem === 'npm'
        ? filterNpmMetadataForCooldown
        : responsePolicy.ecosystem === 'pypi'
          ? filterPypiSimpleMetadataForCooldown
          : null
      if (!filter) return { modified: false, body }
      const result = filter(body, {
        days: cooldown.days,
        now: now(),
        packageName: responsePolicy.name,
      })
      if (result.modified) {
        const responseHeaders = normalizeHeaderBag(headers)
        responseHeaders['cache-control'] = 'no-store'
        delete responseHeaders.etag
        delete responseHeaders['content-encoding']
        delete responseHeaders['content-length']
        emit('supply_chain.dependency_cooldown.filtered', {
          package: result.package,
          stripped: result.stripped,
          remaining: result.remaining,
          strippedVersions: result.strippedVersions,
          cooldownDays: cooldown.days,
          statusCode,
        })
        return { ...result, headers: responseHeaders }
      }
      return result
    },
    async evaluatePackageFetch(pkg, context = {}) {
      const normalizedPkg = {
        ...pkg,
        ecosystem: String(pkg.ecosystem || '').toLowerCase(),
        name: normalizePackageName(pkg.ecosystem, pkg.name),
        version: String(pkg.version || '').trim(),
      }
      normalizedPkg.purl = packagePurl(normalizedPkg)
      const threatDecision = await evaluateThreatIntel(normalizedPkg, context)
      if (threatDecision?.allowed === false) {
        emit('supply_chain.threat_intel.blocked', {
          package: normalizedPkg,
          reason: threatDecision.reason,
          summary: threatDecision.summary,
          referenceUrl: threatDecision.referenceUrl || '',
          source: threatDecision.source || '',
        })
        return threatDecision
      }
      const cooldownDecision = evaluateCooldownFetch(normalizedPkg)
      if (cooldownDecision?.allowed === false) {
        emit('supply_chain.dependency_cooldown.blocked', {
          package: normalizedPkg,
          ...cooldownDecision.cooldown,
        })
        return cooldownDecision
      }
      return { allowed: true, reason: 'package-policy' }
    },
  }
}
