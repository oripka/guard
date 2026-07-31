import crypto from 'node:crypto'
import path from 'node:path'

export const SECURITY_TELEMETRY_VERSION = 1
export const SECURITY_FINDING_SCHEMA_VERSION = 1
export const POLICY_PROPOSAL_SCHEMA_VERSION = 1

const MAX_ARGUMENTS = 128
const MAX_ARGUMENT_LENGTH = 512
const MAX_EVENT_TEXT = 1024
const MAX_EVIDENCE_EVENTS = 500

const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

const sha256 = (value) =>
  crypto.createHash('sha256').update(String(value)).digest('hex')

const boundedText = (value, limit = MAX_EVENT_TEXT) =>
  String(value ?? '').replaceAll('\u0000', '').slice(0, limit)

const sensitiveFlag = (value) =>
  /(?:password|passwd|passphrase|secret|token|api[-_]?key|private[-_]?key|credential|authorization|cookie|session)/i.test(value)

const looksLikeSecretValue = (value) =>
  /^(?:gh[opsu]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-|Bearer\s+|AKIA[A-Z0-9]{16})/.test(value)

const redactInlineAssignment = (value) => {
  const separator = value.indexOf('=')
  if (separator <= 0) return null
  const key = value.slice(0, separator)
  if (!sensitiveFlag(key)) return null
  return `${key}=[REDACTED]`
}

export const redactProcessArguments = (argumentsList = []) => {
  const values = Array.isArray(argumentsList) ? argumentsList : []
  let redactNext = false
  return values.slice(0, MAX_ARGUMENTS).map((rawValue, index) => {
    const original = boundedText(rawValue, MAX_ARGUMENT_LENGTH)
    const inline = redactInlineAssignment(original)
    let value = original
    let redacted = false
    let reason = ''

    if (redactNext) {
      value = '[REDACTED]'
      redacted = true
      reason = 'sensitive-flag-value'
      redactNext = false
    } else if (inline) {
      value = inline
      redacted = true
      reason = 'sensitive-assignment'
    } else if (sensitiveFlag(original) && /^--?[^=]+$/.test(original)) {
      redactNext = true
    } else if (looksLikeSecretValue(original)) {
      value = '[REDACTED]'
      redacted = true
      reason = 'credential-shaped-value'
    } else {
      try {
        const url = new URL(original)
        if (url.username || url.password) {
          url.username = url.username ? '[REDACTED]' : ''
          url.password = url.password ? '[REDACTED]' : ''
          value = url.toString()
          redacted = true
          reason = 'url-userinfo'
        }
      } catch {}
    }

    return {
      index,
      value,
      redacted,
      ...(reason ? { reason } : {}),
      truncated: String(rawValue ?? '').length > MAX_ARGUMENT_LENGTH,
    }
  })
}

export const policySnapshotId = (policy = {}) =>
  `policy_${sha256(stableJson(policy)).slice(0, 20)}`

export const commandFingerprint = (argumentsList = []) =>
  `command_${sha256(stableJson(Array.isArray(argumentsList) ? argumentsList : [])).slice(0, 20)}`

export const createTelemetryContext = ({
  runId = '',
  policy = {},
  idFactory = () => crypto.randomUUID(),
  monotonicClock = () => process.hrtime.bigint(),
} = {}) => {
  const resolvedRunId = boundedText(runId, 160) || `run_${idFactory()}`
  const snapshotId = policySnapshotId(policy)
  let sequence = 0
  let causalParentEventId = ''

  return {
    runId: resolvedRunId,
    policySnapshotId: snapshotId,
    get sequence() {
      return sequence
    },
    get causalParentEventId() {
      return causalParentEventId
    },
    setCausalParent(eventId = '') {
      causalParentEventId = boundedText(eventId, 160)
    },
    decorate(event = {}, { parentEventId, becomesCausalParent = false } = {}) {
      sequence += 1
      const eventId = `evt_${idFactory()}`
      const decorated = {
        ...event,
        telemetryVersion: SECURITY_TELEMETRY_VERSION,
        eventId,
        runId: resolvedRunId,
        sequence,
        parentEventId: boundedText(
          parentEventId === undefined ? causalParentEventId : parentEventId,
          160,
        ),
        monotonicNs: String(monotonicClock()),
        policySnapshotId: snapshotId,
      }
      if (becomesCausalParent) causalParentEventId = eventId
      return decorated
    },
  }
}

const pseudonym = (salt, kind, value) =>
  `${kind}_${crypto.createHmac('sha256', salt).update(String(value)).digest('hex').slice(0, 16)}`

const basenameOrEmpty = (value) => {
  const text = boundedText(value)
  return text ? path.basename(text) : ''
}

export const projectSecurityEvent = (
  event = {},
  { privacy = 'local', pseudonymSalt = '' } = {},
) => {
  const usePseudonyms = privacy === 'pseudonymous'
  const salt = pseudonymSalt || 'guard-local-telemetry'
  const mapIdentity = (kind, value) => {
    const text = boundedText(value)
    if (!text) return ''
    if (usePseudonyms) return pseudonym(salt, kind, text)
    return text
  }
  const processIdentity = event.processIdentity && typeof event.processIdentity === 'object'
    ? event.processIdentity
    : {}
  const signature = processIdentity.signature && typeof processIdentity.signature === 'object'
    ? processIdentity.signature
    : {}

  return {
    schemaVersion: SECURITY_TELEMETRY_VERSION,
    eventId: boundedText(event.eventId, 160),
    runId: boundedText(event.runId, 160),
    sequence: Number.isInteger(event.sequence) ? event.sequence : 0,
    parentEventId: boundedText(event.parentEventId, 160),
    at: boundedText(event.at, 64),
    type: boundedText(event.type, 160),
    profile: mapIdentity('profile', event.profile),
    project: privacy === 'local'
      ? boundedText(event.projectDir)
      : mapIdentity('project', event.projectDir),
    process: {
      pid: Number(event.pid) || 0,
      parentPid: Number(event.parentPid) || 0,
      responsiblePid: Number(event.responsiblePid) || 0,
      executable: privacy === 'local'
        ? boundedText(event.processPath)
        : basenameOrEmpty(event.processPath),
      sha256: boundedText(processIdentity.sha256, 128),
      signingIdentifier: boundedText(signature.identifier, 256),
      teamId: boundedText(signature.teamId, 64),
      signed: signature.signed === true,
      arguments: Array.isArray(event.processArguments)
        ? event.processArguments.slice(0, MAX_ARGUMENTS)
        : [],
      commandFingerprint: boundedText(event.commandFingerprint, 128),
    },
    resource: {
      kind: boundedText(event.resourceKind || event.category, 80),
      target: privacy === 'local'
        ? boundedText(event.target)
        : mapIdentity('resource', event.target),
      sensitivity: boundedText(event.sensitivity, 80),
    },
    network: {
      direction: boundedText(event.direction, 32),
      host: mapIdentity('host', event.host),
      ip: mapIdentity('ip', event.destinationIp || event.ip),
      port: Number(event.port) || 0,
      protocol: boundedText(event.protocol, 32),
      transport: boundedText(event.transport, 48),
      route: boundedText(event.route || event.proxyStatus, 48),
      tlsInspection: boundedText(event.tlsInspectionStatus, 48),
      bytesSent: Number(event.bytesSent) || 0,
      bytesReceived: Number(event.bytesReceived) || 0,
      durationMs: Number(event.durationMs) || 0,
    },
    policy: {
      snapshotId: boundedText(event.policySnapshotId, 128),
      ruleId: boundedText(event.ruleId || event.matchedRuleId, 160),
      result: boundedText(event.result || event.status, 64),
    },
  }
}

const eventTime = (event) => {
  const time = Date.parse(event.at || '')
  return Number.isFinite(time) ? time : 0
}

export const buildEvidenceWindows = (
  events = [],
  { windowMs = 5 * 60 * 1000, maxEvents = MAX_EVIDENCE_EVENTS } = {},
) => {
  const boundedWindowMs = Math.max(1_000, Math.min(Number(windowMs) || 300_000, 60 * 60 * 1000))
  const ordered = [...(Array.isArray(events) ? events : [])]
    .filter((event) => event && event.eventId && event.at)
    .sort((left, right) => eventTime(left) - eventTime(right) || Number(left.sequence || 0) - Number(right.sequence || 0))
    .slice(-Math.max(1, Math.min(Number(maxEvents) || MAX_EVIDENCE_EVENTS, MAX_EVIDENCE_EVENTS)))
  const windows = new Map()

  for (const event of ordered) {
    const at = eventTime(event)
    const bucket = Math.floor(at / boundedWindowMs)
    const runId = boundedText(event.runId, 160) || 'run_unknown'
    const key = `${runId}:${bucket}`
    if (!windows.has(key)) {
      windows.set(key, {
        schemaVersion: SECURITY_TELEMETRY_VERSION,
        id: `window_${sha256(key).slice(0, 20)}`,
        runId,
        startAt: new Date(bucket * boundedWindowMs).toISOString(),
        endAt: new Date((bucket + 1) * boundedWindowMs).toISOString(),
        eventIds: [],
        types: {},
        processIds: [],
        destinations: [],
        sensitiveAccesses: [],
        bytesSent: 0,
        bytesReceived: 0,
        deniedCount: 0,
        limitations: [],
      })
    }
    const window = windows.get(key)
    window.eventIds.push(event.eventId)
    window.types[event.type] = (window.types[event.type] || 0) + 1
    const pid = Number(event.pid || event.process?.pid) || 0
    if (pid > 0 && !window.processIds.includes(pid)) {
      window.processIds.push(pid)
    }
    const destination = boundedText(
      event.host ||
      event.destinationIp ||
      event.ip ||
      event.network?.host ||
      event.network?.ip,
      512,
    )
    if (destination && !window.destinations.includes(destination)) window.destinations.push(destination)
    const sensitivity = boundedText(event.sensitivity || event.resource?.sensitivity, 80)
    if (sensitivity && !window.sensitiveAccesses.includes(sensitivity)) {
      window.sensitiveAccesses.push(sensitivity)
    }
    window.bytesSent += Number(event.bytesSent || event.network?.bytesSent) || 0
    window.bytesReceived += Number(event.bytesReceived || event.network?.bytesReceived) || 0
    const result = event.result || event.status || event.policy?.result
    if (['deny', 'denied', 'blocked'].includes(String(result).toLowerCase())) {
      window.deniedCount += 1
    }
  }

  for (const window of windows.values()) {
    if (window.sensitiveAccesses.length > 0 && window.bytesSent === 0) {
      window.limitations.push('Sensitive access was observed without attributable outbound byte telemetry.')
    }
  }
  return [...windows.values()]
}

const FINDING_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical'])

export const validateSecurityFinding = (finding = {}, knownEventIds = null) => {
  const errors = []
  const eventIds = Array.isArray(finding.eventIds)
    ? [...new Set(finding.eventIds.map((value) => boundedText(value, 160)).filter(Boolean))]
    : []
  const checkKnownEvidence = Array.isArray(knownEventIds)
  const known = new Set(checkKnownEvidence ? knownEventIds : [])
  if (finding.schemaVersion !== SECURITY_FINDING_SCHEMA_VERSION) errors.push('unsupported schemaVersion')
  if (!FINDING_SEVERITIES.has(finding.severity)) errors.push('invalid severity')
  if (!Number.isFinite(finding.confidence) || finding.confidence < 0 || finding.confidence > 1) {
    errors.push('confidence must be between 0 and 1')
  }
  if (!boundedText(finding.title, 240)) errors.push('title is required')
  if (eventIds.length === 0) errors.push('at least one evidence eventId is required')
  if (checkKnownEvidence && eventIds.some((eventId) => !known.has(eventId))) {
    errors.push('finding references unknown eventIds')
  }
  if (!Array.isArray(finding.observations) || finding.observations.length === 0) {
    errors.push('observations are required')
  }
  return {
    ok: errors.length === 0,
    errors,
    value: {
      schemaVersion: SECURITY_FINDING_SCHEMA_VERSION,
      severity: FINDING_SEVERITIES.has(finding.severity) ? finding.severity : 'info',
      confidence: Number.isFinite(finding.confidence) ? finding.confidence : 0,
      title: boundedText(finding.title, 240),
      eventIds,
      observations: (Array.isArray(finding.observations) ? finding.observations : [])
        .slice(0, 32)
        .map((value) => boundedText(value, 500)),
      hypothesis: boundedText(finding.hypothesis, 1000),
      coverageLimitations: (Array.isArray(finding.coverageLimitations) ? finding.coverageLimitations : [])
        .slice(0, 16)
        .map((value) => boundedText(value, 500)),
      recommendedActions: (Array.isArray(finding.recommendedActions) ? finding.recommendedActions : [])
        .slice(0, 16)
        .map((value) => boundedText(value, 500)),
    },
  }
}

const PROPOSABLE_FIELDS = new Set([
  'network.allowedDomains',
  'network.deniedDomains',
  'network.httpRules',
  'filesystem.allowRead',
  'filesystem.allowWrite',
  'filesystem.denyRead',
  'filesystem.denyWrite',
  'subprocess.allowExecutables',
  'subprocess.denyExecutables',
])

const dangerouslyBroadValue = (field, value) => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase()
    if (['*', '**', '/', '0.0.0.0/0', '::/0', 'any', 'all'].includes(normalized)) return true
    if (field.startsWith('filesystem.') && path.resolve(value) === '/') return true
  }
  if (value && typeof value === 'object') {
    const host = String(value.host || '').trim().toLowerCase()
    if (['*', '**', '0.0.0.0/0', '::/0'].includes(host)) return true
  }
  return false
}

const proposalValueErrors = (field, value) => {
  const errors = []
  if (field === 'network.allowedDomains' || field === 'network.deniedDomains') {
    if (typeof value !== 'string' || !value.trim()) {
      errors.push('domain proposal value must be a non-empty string')
    } else if (
      value.includes('://') ||
      value.includes('/') ||
      /\s/.test(value) ||
      (value.includes('*') && !value.startsWith('*.'))
    ) {
      errors.push('domain proposal value must be an exact host or leading wildcard domain')
    }
  } else if (field === 'network.httpRules') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('HTTP rule proposal value must be an object')
    } else {
      const host = String(value.host || '').trim()
      const method = String(value.method || '').trim()
      const requestPath = String(value.path || '').trim()
      if (!host || host.includes('://') || host.includes('/') || /\s/.test(host)) {
        errors.push('HTTP rule proposal requires a host scope')
      }
      if (method && method !== '*' && !/^[A-Z]+$/.test(method)) {
        errors.push('HTTP rule method must be uppercase or *')
      }
      if (requestPath && requestPath !== '*' && !requestPath.startsWith('/')) {
        errors.push('HTTP rule path must start with / or be *')
      }
    }
  } else if (field?.startsWith('filesystem.')) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) {
      errors.push('filesystem proposal value must be an absolute path')
    }
  } else if (field?.startsWith('subprocess.')) {
    if (typeof value !== 'string' || !value.trim() || value.includes('\u0000')) {
      errors.push('subprocess proposal value must be a non-empty executable identity')
    }
  }
  return errors
}

export const validatePolicyProposal = (proposal = {}, knownEventIds = null) => {
  const errors = []
  const evidenceEventIds = Array.isArray(proposal.evidenceEventIds)
    ? [...new Set(proposal.evidenceEventIds.map((value) => boundedText(value, 160)).filter(Boolean))]
    : []
  const checkKnownEvidence = Array.isArray(knownEventIds)
  const known = new Set(checkKnownEvidence ? knownEventIds : [])
  if (proposal.schemaVersion !== POLICY_PROPOSAL_SCHEMA_VERSION) errors.push('unsupported schemaVersion')
  if (proposal.operation !== 'add') errors.push('only additive narrow rule proposals are supported')
  if (!PROPOSABLE_FIELDS.has(proposal.field)) errors.push('field is not proposal-safe')
  if (proposal.value === undefined || proposal.value === null || proposal.value === '') errors.push('value is required')
  if (dangerouslyBroadValue(proposal.field, proposal.value)) errors.push('broad rule proposals are not allowed')
  errors.push(...proposalValueErrors(proposal.field, proposal.value))
  if (evidenceEventIds.length === 0) errors.push('evidenceEventIds are required')
  if (checkKnownEvidence && evidenceEventIds.some((eventId) => !known.has(eventId))) {
    errors.push('proposal references unknown eventIds')
  }
  return {
    ok: errors.length === 0,
    errors,
    value: {
      schemaVersion: POLICY_PROPOSAL_SCHEMA_VERSION,
      type: 'guard.policy.proposal',
      operation: 'add',
      field: boundedText(proposal.field, 120),
      value: proposal.value,
      profile: boundedText(proposal.profile || 'guard', 160),
      evidenceEventIds,
      rationale: boundedText(proposal.rationale, 1000),
      requiresHumanApproval: true,
    },
  }
}
