import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

export const MUTABLE_PROFILE_ARRAY_FIELDS = new Set([
  'network.allowedDomains',
  'network.deniedDomains',
  'filesystem.allowRead',
  'filesystem.denyRead',
  'filesystem.allowWrite',
  'filesystem.denyWrite',
  'process.allowedExecutables',
])

export const readJsonFile = (filePath) => JSON.parse(fs.readFileSync(filePath, 'utf8'))

export const writeJsonFile = (filePath, value) => {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`)
}

export const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

export const ruleHash = (value) =>
  crypto.createHash('sha256').update(stableJson(value)).digest('hex')

export const normalizeProfilePort = (port, label = 'port') => {
  const value = Number(port)
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`invalid ${label}: ${port}`)
  }
  return value
}

export const normalizeHttpRule = (rule = {}) => {
  const host = typeof rule.host === 'string' ? rule.host.trim().toLowerCase() : ''
  const cidr = typeof rule.cidr === 'string' ? rule.cidr.trim() : ''
  if ((!host && !cidr) || (host && cidr)) {
    throw new Error('HTTP rules require exactly one of --host or --cidr')
  }
  const normalized = host ? { host } : { cidr }
  const methods = Array.isArray(rule.methods)
    ? rule.methods.map((value) => String(value).trim().toUpperCase()).filter(Boolean)
    : []
  const paths = Array.isArray(rule.paths)
    ? rule.paths.map((value) => String(value).trim()).filter(Boolean)
    : []
  if (methods.length > 0) normalized.methods = [...new Set(methods)]
  if (paths.length > 0) normalized.paths = [...new Set(paths)]
  return normalized
}

export const normalizeRawTcpRule = (rule = {}) => {
  const host = typeof rule.host === 'string' ? rule.host.trim().toLowerCase() : ''
  const ip = typeof rule.ip === 'string' ? rule.ip.trim() : ''
  if ((!host && !ip) || (host && ip)) {
    throw new Error('raw TCP rules require exactly one of --host or --ip')
  }
  const normalized = host ? { host } : { ip }
  if (host) normalized.resolveAtLaunch = rule.resolveAtLaunch === true
  normalized.port = normalizeProfilePort(rule.port, 'raw TCP port')
  if (typeof rule.reason === 'string' && rule.reason.trim()) {
    normalized.reason = rule.reason.trim()
  }
  return normalized
}

export const canonicalRuleValue = (field, value) =>
  field === 'network.httpRules'
    ? normalizeHttpRule(value)
    : field === 'network.allowedRawTcp'
      ? normalizeRawTcpRule(value)
      : String(value)

export const ruleMetadataKey = (field, value) =>
  `${field}:${ruleHash(canonicalRuleValue(field, value)).slice(0, 16)}`

export const profileVersion = (config) => `sha256:${ruleHash(config)}`

export const profileVersionInfo = (config) => {
  const hash = ruleHash(config)
  return {
    version: `sha256:${hash}`,
    hash: `sha256:${hash}`,
    shortHash: hash.slice(0, 16),
  }
}

export const ensurePathArray = (cfg, field, create) => {
  const [section, key] = field.split('.')
  if (!cfg[section]) {
    if (!create) return null
    cfg[section] = {}
  }
  if (!Array.isArray(cfg[section][key])) {
    if (!create) return null
    cfg[section][key] = []
  }
  return cfg[section][key]
}

export const ensureRuleMetadata = (cfg, field, value, source = 'cli') => {
  const canonical = canonicalRuleValue(field, value)
  const hash = ruleHash(canonical)
  const key = `${field}:${hash.slice(0, 16)}`
  if (!cfg.ruleMetadata || typeof cfg.ruleMetadata !== 'object' || Array.isArray(cfg.ruleMetadata)) {
    cfg.ruleMetadata = {}
  }
  const existing = cfg.ruleMetadata[key] && typeof cfg.ruleMetadata[key] === 'object'
    ? cfg.ruleMetadata[key]
    : {}
  const now = new Date().toISOString()
  cfg.ruleMetadata[key] = {
    ...existing,
    id: `rule_${hash.slice(0, 16)}`,
    field,
    value: structuredClone(canonical),
    valueHash: `sha256:${hash}`,
    layer: existing.layer || ruleLayerForField(field),
    action: existing.action || ruleActionForField(field, canonical),
    scope: existing.scope || ruleScopeForField(field, canonical),
    lifetime: existing.lifetime || 'persistent',
    approvalState: existing.approvalState || 'approved',
    notes: typeof existing.notes === 'string' ? existing.notes : '',
    auditHistory: Array.isArray(existing.auditHistory) ? existing.auditHistory : [],
    createdAt: existing.createdAt || now,
    updatedAt: now,
    source: existing.source || source,
    disabled: existing.disabled === true,
  }
  return { metadataKey: key, ruleId: cfg.ruleMetadata[key].id }
}

export const ruleLayerForField = (field) => {
  if (field.startsWith('filesystem.')) return 'filesystem'
  if (field.startsWith('process.')) return 'process'
  if (field === 'network.httpRules') return 'http'
  if (field === 'network.allowedRawTcp') return 'raw-tcp'
  if (field.startsWith('network.')) return 'destination'
  return 'profile'
}

export const ruleActionForField = (field, value) => {
  if (field.includes('.deny') || field === 'network.deniedDomains') return 'deny'
  if (field === 'network.secretInjection') return 'inject'
  if (value && typeof value === 'object' && typeof value.action === 'string') return value.action
  return 'allow'
}

export const ruleScopeForField = (field, value) => {
  if (typeof value === 'string') return value
  if (field === 'network.httpRules') {
    const host = value.host || value.cidr || '*'
    const method = Array.isArray(value.methods) && value.methods.length > 0 ? value.methods.join(',') : '*'
    const paths = Array.isArray(value.paths) && value.paths.length > 0 ? value.paths.join(',') : '/*'
    return `${method} ${host}${paths === '/*' ? '' : ` ${paths}`}`
  }
  if (field === 'network.allowedRawTcp') {
    return `${value.host || value.ip || '*'}:${value.port || '*'}`
  }
  return stableJson(value)
}

export const typedRuleFromProfileValue = ({ field, value, metadata = {}, source = 'profile' }) => {
  const canonical = canonicalRuleValue(field, value)
  const key = ruleMetadataKey(field, canonical)
  const hash = ruleHash(canonical)
  const meta = metadata[key] && typeof metadata[key] === 'object' ? metadata[key] : {}
  return {
    schemaVersion: 1,
    id: meta.id || `rule_${hash.slice(0, 16)}`,
    metadataKey: key,
    field,
    layer: meta.layer || ruleLayerForField(field),
    action: meta.action || ruleActionForField(field, canonical),
    scope: meta.scope || ruleScopeForField(field, canonical),
    value: canonical,
    source: meta.source || source,
    enabled: meta.disabled !== true,
    lifetime: meta.lifetime || 'persistent',
    approvalState: meta.approvalState || 'approved',
    notes: typeof meta.notes === 'string' ? meta.notes : '',
    processIdentity: meta.processIdentity && typeof meta.processIdentity === 'object' ? meta.processIdentity : null,
    createdAt: meta.createdAt || '',
    updatedAt: meta.updatedAt || '',
    auditHistory: Array.isArray(meta.auditHistory) ? meta.auditHistory : [],
  }
}

export const buildTypedRules = (config = {}, { source = 'profile' } = {}) => {
  const network = config.network || {}
  const filesystem = config.filesystem || {}
  const metadata = config.ruleMetadata && typeof config.ruleMetadata === 'object' && !Array.isArray(config.ruleMetadata)
    ? config.ruleMetadata
    : {}
  const rules = []
  const addValues = (field, values = []) => {
    for (const value of Array.isArray(values) ? values : []) {
      rules.push(typedRuleFromProfileValue({ field, value, metadata, source }))
    }
  }
  addValues('network.allowedDomains', network.allowedDomains)
  addValues('network.deniedDomains', network.deniedDomains)
  addValues('network.httpRules', network.httpRules)
  addValues('network.allowedRawTcp', network.allowedRawTcp)
  addValues('filesystem.allowRead', filesystem.allowRead)
  addValues('filesystem.denyRead', filesystem.denyRead)
  addValues('filesystem.allowWrite', filesystem.allowWrite)
  addValues('filesystem.denyWrite', filesystem.denyWrite)
  addValues('process.allowedExecutables', config.process?.allowedExecutables)

  for (const [key, meta] of Object.entries(metadata)) {
    if (!meta || typeof meta !== 'object' || meta.disabled !== true) continue
    if (rules.some((rule) => rule.metadataKey === key)) continue
    const field = typeof meta.field === 'string' ? meta.field : key.split(':')[0]
    rules.push({
      schemaVersion: 1,
      id: meta.id || `rule_${key.split(':')[1] || ruleHash(key).slice(0, 16)}`,
      metadataKey: key,
      field,
      layer: meta.layer || ruleLayerForField(field),
      action: meta.action || 'allow',
      scope: meta.scope || ruleScopeForField(field, meta.value ?? key),
      value: meta.value ?? key,
      source: meta.source || source,
      enabled: false,
      lifetime: meta.lifetime || 'persistent',
      approvalState: meta.approvalState || 'approved',
      notes: typeof meta.notes === 'string' ? meta.notes : '',
      processIdentity: meta.processIdentity && typeof meta.processIdentity === 'object' ? meta.processIdentity : null,
      createdAt: meta.createdAt || '',
      updatedAt: meta.updatedAt || '',
      auditHistory: Array.isArray(meta.auditHistory) ? meta.auditHistory : [],
    })
  }

  return rules.sort((left, right) =>
    `${left.enabled ? '0' : '1'}:${left.layer}:${left.action}:${left.scope}`
      .localeCompare(`${right.enabled ? '0' : '1'}:${right.layer}:${right.action}:${right.scope}`),
  )
}

const plainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

const numberOrZero = (value) => {
  const parsed = Number(value)
  return Number.isInteger(parsed) ? parsed : 0
}

export const normalizeDecisionSubject = (subject = {}, fallback = {}) => ({
  kind: String(subject.kind || fallback.kind || 'process'),
  pid: numberOrZero(subject.pid ?? fallback.pid),
  ppid: numberOrZero(subject.ppid ?? fallback.ppid),
  executablePath: String(subject.executablePath || fallback.executablePath || fallback.command || ''),
  commandLine: String(subject.commandLine || fallback.commandLine || fallback.command || ''),
  bundleId: String(subject.bundleId || fallback.bundleId || ''),
  teamId: String(subject.teamId || fallback.teamId || ''),
  signingStatus: String(subject.signingStatus || fallback.signingStatus || 'unknown'),
  projectDir: String(subject.projectDir || fallback.projectDir || ''),
  profile: String(subject.profile || fallback.profile || 'guard'),
  parentChain: String(subject.parentChain || fallback.parentChain || ''),
  launcherApp: String(subject.launcherApp || fallback.launcherApp || ''),
  launcherProcess: String(subject.launcherProcess || fallback.launcherProcess || ''),
  launcherPid: numberOrZero(subject.launcherPid ?? fallback.launcherPid),
})

const inferOperationKind = (body = {}, resource = {}) => {
  if (body.operationKind) return String(body.operationKind)
  if (body.kind && String(body.kind).includes('.')) return String(body.kind)
  if (resource.kind === 'http' || body.method || body.path) return 'http.request'
  if (resource.kind === 'tls') return 'tls.inspect'
  if (resource.kind === 'network') return 'network.connect'
  return 'network.connect'
}

export const normalizeDecisionOperation = (operation = {}, fallback = {}) => {
  const kind = String(operation.kind || inferOperationKind(fallback, fallback.resource || {}))
  return {
    kind,
    direction: String(operation.direction || fallback.direction || (kind.startsWith('network.') || kind === 'http.request' ? 'outbound' : '')),
    intent: String(operation.intent || fallback.intent || kind.split('.').at(-1) || ''),
  }
}

export const normalizeDecisionResource = (resource = {}, fallback = {}) => {
  const fallbackHost = String(fallback.host || '')
  const inferredKind = resource.kind ||
    (fallback.method || fallback.path ? 'http' : 'network')
  const kind = String(inferredKind)
  if (kind === 'http') {
    return {
      kind,
      scheme: String(resource.scheme || fallback.scheme || (Number(fallback.port) === 80 ? 'http' : 'https')),
      host: String(resource.host || fallbackHost).toLowerCase(),
      port: numberOrZero(resource.port ?? fallback.port),
      method: String(resource.method || fallback.method || '').toUpperCase(),
      path: String(resource.path || fallback.path || ''),
      tlsInspection: String(resource.tlsInspection || fallback.tlsInspection || ''),
    }
  }
  if (kind === 'tls') {
    return {
      kind,
      host: String(resource.host || fallbackHost).toLowerCase(),
      port: numberOrZero(resource.port ?? fallback.port),
      tlsInspection: String(resource.tlsInspection || fallback.tlsInspection || 'unknown'),
      failureReason: String(resource.failureReason || fallback.failureReason || ''),
    }
  }
  return {
    kind: 'network',
    host: String(resource.host || fallbackHost).toLowerCase(),
    ip: String(resource.ip || fallback.ip || ''),
    port: numberOrZero(resource.port ?? fallback.port),
    protocol: String(resource.protocol || fallback.protocol || ''),
    direction: String(resource.direction || fallback.direction || 'outbound'),
  }
}

export const normalizeDecisionRequest = (body = {}) => {
  const input = plainObject(body.decisionRequest) ? body.decisionRequest : body
  const fallback = { ...body, ...input }
  const resource = normalizeDecisionResource(plainObject(input.resource) ? input.resource : {}, fallback)
  const operation = normalizeDecisionOperation(plainObject(input.operation) ? input.operation : {}, { ...fallback, resource })
  const subject = normalizeDecisionSubject(plainObject(input.subject) ? input.subject : {}, fallback)
  return {
    schemaVersion: 1,
    contractVersion: 1,
    id: String(input.id || body.decisionId || `decision_${ruleHash({ subject, operation, resource }).slice(0, 16)}`),
    source: String(input.source || body.source || body.backend || 'guardd'),
    mode: String(input.mode || body.mode || 'per-run'),
    subject,
    operation,
    resource,
    context: plainObject(input.context) ? structuredClone(input.context) : {},
    recommendedScopes: Array.isArray(input.recommendedScopes)
      ? input.recommendedScopes.map(String)
      : operation.kind === 'http.request'
        ? ['exact', 'path', 'domain', 'process', 'project']
        : ['exact', 'process', 'project'],
    defaultAction: String(input.defaultAction || body.defaultAction || 'ask'),
  }
}

export const setRuleMetadataDisabled = (cfg, field, value, disabled, source = 'cli') => {
  const metadata = ensureRuleMetadata(cfg, field, value, source)
  const wasDisabled = cfg.ruleMetadata[metadata.metadataKey].disabled === true
  cfg.ruleMetadata[metadata.metadataKey].disabled = Boolean(disabled)
  cfg.ruleMetadata[metadata.metadataKey].updatedAt = new Date().toISOString()
  return { ...metadata, metadataChanged: wasDisabled !== Boolean(disabled) }
}

export const removeRuleMetadata = (cfg, field, value) => {
  const key = ruleMetadataKey(field, value)
  if (cfg.ruleMetadata && typeof cfg.ruleMetadata === 'object' && !Array.isArray(cfg.ruleMetadata)) {
    delete cfg.ruleMetadata[key]
  }
  return { metadataKey: key, ruleId: `rule_${key.split(':')[1]}` }
}

export const mutateArrayRuleConfig = ({
  cfg,
  field,
  value,
  action,
  disabled = false,
  source = 'cli',
}) => {
  if (!MUTABLE_PROFILE_ARRAY_FIELDS.has(field)) {
    throw new Error(`unsupported profile field: ${field}`)
  }
  const normalizedValue = String(value)
  const values = ensurePathArray(cfg, field, action === 'add' || action === 'enable')
  const before = values ? [...values] : []
  let changed = false

  if (action === 'add' || action === 'enable') {
    if (disabled === true) {
      const next = values.filter((entry) => entry !== normalizedValue)
      changed = next.length !== values.length
      if (changed) values.splice(0, values.length, ...next)
    } else if (!values.includes(normalizedValue)) {
      values.push(normalizedValue)
      changed = true
    }
    const { metadataChanged, ...metadata } = setRuleMetadataDisabled(
      cfg,
      field,
      normalizedValue,
      disabled === true,
      source,
    )
    changed = changed || metadataChanged
    return {
      action,
      changed,
      field,
      value: normalizedValue,
      disabled: disabled === true,
      ...metadata,
      before,
      after: ensurePathArray(cfg, field, false) || [],
    }
  }

  if (values) {
    const next = values.filter((entry) => entry !== normalizedValue)
    changed = next.length !== values.length
    if (changed) values.splice(0, values.length, ...next)
  }

  if (action === 'disable') {
    const { metadataChanged: _metadataChanged, ...metadata } = setRuleMetadataDisabled(
      cfg,
      field,
      normalizedValue,
      true,
      source,
    )
    return {
      action,
      changed: true,
      field,
      value: normalizedValue,
      disabled: true,
      ...metadata,
      before,
      after: ensurePathArray(cfg, field, false) || [],
    }
  }

  if (action !== 'remove') throw new Error(`unsupported rule action: ${action}`)

  const metadata = changed
    ? removeRuleMetadata(cfg, field, normalizedValue)
    : {
        metadataKey: ruleMetadataKey(field, normalizedValue),
        ruleId: `rule_${ruleMetadataKey(field, normalizedValue).split(':')[1]}`,
      }
  return {
    action,
    changed,
    field,
    value: normalizedValue,
    disabled: false,
    ...metadata,
    before,
    after: ensurePathArray(cfg, field, false) || [],
  }
}

export const mutateHttpRuleConfig = ({
  cfg,
  rule,
  action,
  disabled = false,
  source = 'cli',
}) => {
  if (!cfg.network) cfg.network = {}
  if (!Array.isArray(cfg.network.httpRules)) cfg.network.httpRules = []
  const normalized = normalizeHttpRule(rule)
  const key = stableJson(normalized)
  const before = [...cfg.network.httpRules]
  const index = cfg.network.httpRules.findIndex(
    (entry) => stableJson(normalizeHttpRule(entry)) === key,
  )
  let changed = false

  if (action === 'add' || action === 'enable') {
    if (disabled === true) {
      if (index !== -1) {
        cfg.network.httpRules.splice(index, 1)
        changed = true
      }
    } else if (index === -1) {
      cfg.network.httpRules.push(normalized)
      changed = true
    }
    const { metadataChanged, ...metadata } = setRuleMetadataDisabled(
      cfg,
      'network.httpRules',
      normalized,
      disabled === true,
      source,
    )
    changed = changed || metadataChanged
    return {
      action,
      changed,
      field: 'network.httpRules',
      value: normalized,
      disabled: disabled === true,
      ...metadata,
      before,
      after: cfg.network.httpRules,
    }
  }

  if (action === 'disable') {
    if (index !== -1) {
      cfg.network.httpRules.splice(index, 1)
      changed = true
    }
    const { metadataChanged: _metadataChanged, ...metadata } = setRuleMetadataDisabled(
      cfg,
      'network.httpRules',
      normalized,
      true,
      source,
    )
    return {
      action,
      changed: true,
      field: 'network.httpRules',
      value: normalized,
      disabled: true,
      ...metadata,
      before,
      after: cfg.network.httpRules,
    }
  }

  if (action !== 'remove') throw new Error(`unsupported rule action: ${action}`)

  if (index !== -1) {
    cfg.network.httpRules.splice(index, 1)
    changed = true
  }
  const metadata = changed
    ? removeRuleMetadata(cfg, 'network.httpRules', normalized)
    : {
        metadataKey: ruleMetadataKey('network.httpRules', normalized),
        ruleId: `rule_${ruleMetadataKey('network.httpRules', normalized).split(':')[1]}`,
      }
  return {
    action,
    changed,
    field: 'network.httpRules',
    value: normalized,
    disabled: false,
    ...metadata,
    before,
    after: cfg.network.httpRules,
  }
}

export const mutateRawTcpRuleConfig = ({ cfg, rule, action, source = 'cli' }) => {
  if (!cfg.network) cfg.network = {}
  if (!Array.isArray(cfg.network.allowedRawTcp)) cfg.network.allowedRawTcp = []
  const normalized = normalizeRawTcpRule(rule)
  const key = stableJson(normalized)
  const before = [...cfg.network.allowedRawTcp]
  const index = cfg.network.allowedRawTcp.findIndex(
    (entry) => stableJson(normalizeRawTcpRule(entry)) === key,
  )
  let changed = false

  if (action === 'add') {
    if (index === -1) {
      cfg.network.allowedRawTcp.push(normalized)
      changed = true
    }
  } else if (action === 'remove') {
    if (index !== -1) {
      cfg.network.allowedRawTcp.splice(index, 1)
      changed = true
    }
  } else {
    throw new Error(`unsupported rule action: ${action}`)
  }

  const metadata = changed
    ? action === 'add'
      ? ensureRuleMetadata(cfg, 'network.allowedRawTcp', normalized, source)
      : removeRuleMetadata(cfg, 'network.allowedRawTcp', normalized)
    : {
        metadataKey: ruleMetadataKey('network.allowedRawTcp', normalized),
        ruleId: `rule_${ruleMetadataKey('network.allowedRawTcp', normalized).split(':')[1]}`,
      }
  return {
    action,
    changed,
    field: 'network.allowedRawTcp',
    value: normalized,
    ruleId: metadata.ruleId,
    metadataKey: metadata.metadataKey,
    before,
    after: cfg.network.allowedRawTcp,
  }
}

export const mutateTlsConfig = ({ cfg, enabled }) => {
  if (!cfg.network) cfg.network = {}
  const before = cfg.network.tlsInspection || {}
  const next = {
    ...(before && typeof before === 'object' && !Array.isArray(before) ? before : {}),
    enabled: Boolean(enabled),
    mode: enabled ? 'ephemeral-run-ca' : 'off',
    caScope: enabled ? 'guarded-process-env' : 'none',
    userApprovalRequired: true,
  }
  const changed = stableJson(before) !== stableJson(next)
  cfg.network.tlsInspection = next
  return {
    action: enabled ? 'enable' : 'disable',
    changed,
    before,
    after: next,
  }
}

export const wildcardMatch = (value, pattern) => {
  const normalizedValue = String(value || '').toLowerCase()
  const normalizedPattern = String(pattern || '').toLowerCase()
  if (!normalizedPattern) return false
  if (normalizedPattern === '*') return true
  if (!normalizedPattern.includes('*')) return normalizedValue === normalizedPattern
  const escaped = normalizedPattern
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*')
  return new RegExp(`^${escaped}$`, 'i').test(normalizedValue)
}

export const hostMatches = (host, pattern) => {
  const normalizedHost = String(host || '').toLowerCase()
  const normalizedPattern = String(pattern || '').toLowerCase()
  if (!normalizedHost || !normalizedPattern) return false
  if (wildcardMatch(normalizedHost, normalizedPattern)) return true
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1)
    return normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length
  }
  return false
}

export const evaluateNetworkPolicy = ({ config = {}, host = '', method = '', path: requestPath = '' }) => {
  const network = config.network || {}
  const normalizedHost = String(host || '').trim().toLowerCase()
  const normalizedMethod = String(method || '').trim().toUpperCase()
  const normalizedPath = String(requestPath || '').trim() || '/'
  const decisionBase = {
    contractVersion: 1,
    evaluator: 'guard-policy',
    layer: 'shared-policy',
    host: normalizedHost,
    method: normalizedMethod,
    path: normalizedPath,
  }

  if (!normalizedHost) {
    return { ...decisionBase, allowed: true, reason: 'no-host', ruleId: '', field: '' }
  }

  for (const pattern of Array.isArray(network.deniedDomains) ? network.deniedDomains : []) {
    if (hostMatches(normalizedHost, pattern)) {
      return {
        ...decisionBase,
        allowed: false,
        reason: 'deniedDomains',
        ruleId: `rule_${ruleHash(String(pattern)).slice(0, 16)}`,
        field: 'network.deniedDomains',
        value: pattern,
      }
    }
  }

  const httpRules = Array.isArray(network.httpRules) ? network.httpRules : []
  if (httpRules.length > 0 && (normalizedMethod || requestPath)) {
    for (const rule of httpRules) {
      const normalizedRule = normalizeHttpRule(rule)
      const ruleHost = normalizedRule.host || normalizedRule.cidr || ''
      if (normalizedRule.host && !hostMatches(normalizedHost, normalizedRule.host)) continue
      if (normalizedRule.cidr && normalizedRule.cidr !== normalizedHost) continue
      if (Array.isArray(normalizedRule.methods) && normalizedRule.methods.length > 0 && !normalizedRule.methods.includes(normalizedMethod)) continue
      if (Array.isArray(normalizedRule.paths) && normalizedRule.paths.length > 0 && !normalizedRule.paths.some((pattern) => wildcardMatch(normalizedPath, pattern))) continue
      return {
        ...decisionBase,
        allowed: true,
        reason: 'httpRules',
        ruleId: `rule_${ruleHash(normalizedRule).slice(0, 16)}`,
        field: 'network.httpRules',
        value: normalizedRule,
        matchedHost: ruleHost,
      }
    }
    return { ...decisionBase, allowed: false, reason: 'httpRules-default-deny', ruleId: '', field: 'network.httpRules' }
  }

  const allowedDomains = Array.isArray(network.allowedDomains) ? network.allowedDomains : []
  if (allowedDomains.length > 0) {
    for (const pattern of allowedDomains) {
      if (hostMatches(normalizedHost, pattern)) {
        return {
          ...decisionBase,
          allowed: true,
          reason: 'allowedDomains',
          ruleId: `rule_${ruleHash(String(pattern)).slice(0, 16)}`,
          field: 'network.allowedDomains',
          value: pattern,
        }
      }
    }
    return { ...decisionBase, allowed: false, reason: 'allowedDomains-default-deny', ruleId: '', field: 'network.allowedDomains' }
  }

  return { ...decisionBase, allowed: true, reason: 'no-network-policy', ruleId: '', field: '' }
}

export const evaluateDecisionRequest = ({ config = {}, request = {} }) => {
  const decisionRequest = normalizeDecisionRequest(request)
  const operationKind = decisionRequest.operation.kind
  const resource = decisionRequest.resource
  const base = {
    contractVersion: 1,
    evaluator: 'guard-policy',
    layer: 'shared-policy',
    decisionRequest,
    operationKind,
    resourceKind: resource.kind,
  }
  if (operationKind === 'http.request') {
    return {
      ...base,
      ...evaluateNetworkPolicy({
        config,
        host: resource.host,
        method: resource.method,
        path: resource.path,
      }),
    }
  }
  if (operationKind === 'network.connect' || operationKind === 'network.listen' || resource.kind === 'network') {
    return {
      ...base,
      ...evaluateNetworkPolicy({
        config,
        host: resource.host || resource.ip,
        method: '',
        path: '',
      }),
    }
  }
  if (operationKind === 'tls.inspect') {
    const tls = config.network?.tlsInspection || {}
    return {
      ...base,
      allowed: tls.failClosedWithoutDecryption === true ? false : true,
      reason: tls.enabled === true ? 'tlsInspection-configured' : 'tlsInspection-not-configured',
      ruleId: '',
      field: 'network.tlsInspection',
    }
  }
  return {
    ...base,
    allowed: false,
    reason: 'unsupported-operation-default-deny',
    ruleId: '',
    field: '',
  }
}

export const decisionContract = () => ({
  contractVersion: 1,
  evaluator: 'guard-policy',
  layer: 'shared-policy',
  defaultFallback: 'daemon-controlled',
  responseFields: [
    'allowed',
    'reason',
    'ruleId',
    'field',
    'value',
    'contractVersion',
    'evaluator',
    'layer',
    'host',
    'method',
    'path',
  ],
})

const normalizeStringArray = (value) =>
  Array.isArray(value)
    ? value.map((entry) => String(entry).trim()).filter(Boolean)
    : []

const normalizeHttpRulesForSnapshot = (value) =>
  Array.isArray(value)
    ? value.map((entry) => normalizeHttpRule(entry))
    : []

const normalizeRawTcpRulesForSnapshot = (value) =>
  Array.isArray(value)
    ? value.map((entry) => normalizeRawTcpRule(entry))
    : []

const normalizeSecretInjectionForSnapshot = (value) =>
  Array.isArray(value)
    ? value
        .filter((entry) => entry && typeof entry === 'object')
        .map((entry) => {
          const source = entry.source && typeof entry.source === 'object' ? entry.source : {}
          const rules = Array.isArray(entry.rules) && entry.rules.length > 0
            ? entry.rules.map((rule) => normalizeHttpRule(rule))
            : entry.host
              ? [normalizeHttpRule({ host: entry.host, methods: entry.methods, paths: entry.paths })]
              : []
          return {
            name: String(entry.name || source.var || source.secret_id || 'secret'),
            sourceType: String(source.type || (entry.env || entry.var ? 'env' : 'unknown')),
            sourceRef: String(source.var || source.secret_id || entry.env || entry.var || ''),
            proxyValueConfigured: Boolean(entry.proxyValue || entry.proxy_value || entry.proxyToken),
            proxyValueExposed: false,
            matchHeaders: normalizeStringArray(entry.matchHeaders || entry.match_headers || ['Authorization']),
            matchBody: entry.matchBody === true || entry.match_body === true,
            require: entry.require === true,
            rules,
          }
        })
    : []

export const buildPolicySnapshot = ({
  config = {},
  profile = 'guard',
  projectDir = '',
  source = '',
  rawVersion = '',
  effectiveVersion = '',
  sequence = 1,
  generatedAt = new Date().toISOString(),
}) => {
  const network = config.network || {}
  const filesystem = config.filesystem || {}
  return {
    schemaVersion: 1,
    contractVersion: 1,
    syncVersion: 1,
    profile,
    projectDir,
    generatedAt,
    sequence,
    version: effectiveVersion,
    metadata: {
      profile,
      projectDir,
      source,
      rawVersion,
      effectiveVersion,
    },
    network: {
      backend: network.backend || 'guard-policy',
      allowedDomains: normalizeStringArray(network.allowedDomains),
      deniedDomains: normalizeStringArray(network.deniedDomains),
      httpRules: normalizeHttpRulesForSnapshot(network.httpRules),
      allowedRawTcp: normalizeRawTcpRulesForSnapshot(network.allowedRawTcp),
      secretInjection: normalizeSecretInjectionForSnapshot(network.secretInjection || network.secrets),
      tlsInspection: network.tlsInspection && typeof network.tlsInspection === 'object'
        ? structuredClone(network.tlsInspection)
        : {},
    },
    filesystem: {
      allowRead: normalizeStringArray(filesystem.allowRead),
      denyRead: normalizeStringArray(filesystem.denyRead),
      allowWrite: normalizeStringArray(filesystem.allowWrite),
      denyWrite: normalizeStringArray(filesystem.denyWrite),
    },
    ruleMetadata: config.ruleMetadata && typeof config.ruleMetadata === 'object' && !Array.isArray(config.ruleMetadata)
      ? structuredClone(config.ruleMetadata)
      : {},
    decisionContract: decisionContract(),
  }
}

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

const mergeUniqueArray = (left = [], right = []) => {
  const values = []
  for (const value of [...left, ...right]) {
    if (!values.includes(value)) values.push(value)
  }
  return values
}

export const mergeProfileConfig = (base = {}, overlay = {}) => {
  const merged = structuredClone(base)
  for (const [key, value] of Object.entries(overlay)) {
    if (key === 'imports') continue
    const current = merged[key]
    if (Array.isArray(current) || Array.isArray(value)) {
      merged[key] = mergeUniqueArray(
        Array.isArray(current) ? current : [],
        Array.isArray(value) ? value : [],
      )
    } else if (isPlainObject(current) && isPlainObject(value)) {
      merged[key] = mergeProfileConfig(current, value)
    } else {
      merged[key] = structuredClone(value)
    }
  }
  return merged
}

export const resolveProfileImportPath = ({ repoRoot, configPath, ref }) => {
  if (typeof ref !== 'string' || !ref.trim()) {
    throw new Error(`invalid profile import in ${configPath}`)
  }

  const value = ref.trim()
  if (path.isAbsolute(value) || value.startsWith('.') || value.includes('/')) {
    return path.resolve(path.dirname(configPath), value)
  }
  return path.resolve(repoRoot, 'templates', 'imports', `${value}.json`)
}

export const loadProfileConfig = ({ repoRoot, configPath, seen = new Set() }) => {
  const normalized = path.resolve(configPath)
  if (seen.has(normalized)) throw new Error(`profile import cycle detected at ${normalized}`)
  seen.add(normalized)

  const cfg = readJsonFile(normalized)
  const imports = Array.isArray(cfg.imports) ? cfg.imports : []
  let merged = {}
  for (const ref of imports) {
    const importPath = resolveProfileImportPath({ repoRoot, configPath: normalized, ref })
    if (!fs.existsSync(importPath)) {
      throw new Error(`unknown profile import "${ref}" from ${normalized}`)
    }
    merged = mergeProfileConfig(
      merged,
      loadProfileConfig({ repoRoot, configPath: importPath, seen }),
    )
  }

  seen.delete(normalized)
  return mergeProfileConfig(merged, cfg)
}
