import { spawn } from 'node:child_process'

const escapePredicateString = (value) => String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')

export const sandboxLogTag = ({ runDir = '', pid = process.pid, random = Math.random } = {}) => {
  const suffix = random().toString(36).slice(2, 10)
  const runName = String(runDir || '')
    .split(/[\\/]/)
    .filter(Boolean)
    .pop()
  return ['guard', pid, runName, suffix].filter(Boolean).join(':')
}

const categoryForOperation = (operation) => {
  if (operation.startsWith('file-read')) return 'filesystem'
  if (operation.startsWith('file-write')) return 'filesystem'
  if (operation.startsWith('process-exec')) return 'process'
  if (operation.startsWith('network-')) return 'network'
  if (operation.startsWith('sysctl-')) return 'system'
  return 'sandbox'
}

export const classifySandboxDenialSensitivity = ({ operation = '', target = '' } = {}) => {
  const op = String(operation || '').toLowerCase()
  const rawTarget = String(target || '')
  const normalized = rawTarget.replace(/\\/g, '/')
  const lower = normalized.toLowerCase()
  const basename = lower.split('/').filter(Boolean).pop() || lower
  const isRead = op.startsWith('file-read')
  const isWrite = op.startsWith('file-write')

  if (/(^|\/)(\.guard-canary|guard-canary|canary)([-_.\/]|$)/.test(lower)) {
    return {
      severity: 'high',
      sensitivity: 'canary-file',
      reason: 'canary-file-access',
      notify: true,
    }
  }

  if (isRead && /\/\.ssh\/(id_(rsa|dsa|ecdsa|ed25519)|identity)(\.|$)?/.test(lower)) {
    return {
      severity: 'high',
      sensitivity: 'ssh-private-key',
      reason: 'ssh-private-key-read',
      notify: true,
    }
  }

  if (isRead && (
    lower.includes('/.aws/credentials') ||
    lower.includes('/.config/gcloud/') ||
    lower.includes('/.azure/') ||
    lower.includes('/.kube/config') ||
    lower.includes('/.docker/config.json') ||
    lower.includes('/.terraform.d/credentials.tfrc.json') ||
    lower.includes('/.config/gh/hosts.yml') ||
    lower.includes('/.cargo/credentials') ||
    lower.includes('/.cargo/credentials.toml') ||
    lower.includes('/.gem/credentials') ||
    lower.includes('/.gnupg/private-keys-v1.d/') ||
    lower.includes('/.npmrc') ||
    lower.includes('/.pypirc') ||
    lower.includes('/.netrc')
  )) {
    return {
      severity: 'high',
      sensitivity: 'credential-file',
      reason: 'credential-file-read',
      notify: true,
    }
  }

  if (isRead && (
    basename.endsWith('.pem') ||
    basename.endsWith('.key') ||
    basename.endsWith('.kdbx') ||
    basename.endsWith('.kdb') ||
    basename.endsWith('.p12') ||
    basename.endsWith('.pfx') ||
    basename === 'known_hosts.old'
  )) {
    if (basename.endsWith('.kdbx') || basename.endsWith('.kdb')) {
      return {
        severity: 'high',
        sensitivity: 'credential-database',
        reason: 'credential-database-read',
        notify: true,
      }
    }
    return {
      severity: 'high',
      sensitivity: 'key-material',
      reason: 'key-material-read',
      notify: true,
    }
  }

  if ((isRead || isWrite) && (basename === '.env' || basename.startsWith('.env.'))) {
    return {
      severity: 'medium',
      sensitivity: 'env-file',
      reason: 'env-file-access',
      notify: false,
    }
  }

  return {
    severity: 'low',
    sensitivity: '',
    reason: '',
    notify: false,
  }
}

export const parseSandboxDenialMessage = (message, expectedTag = '') => {
  const text = String(message || '')
  if (expectedTag && !text.includes(expectedTag)) return null
  const line = text
    .split(/\r?\n/)
    .map((part) => part.trim())
    .find((part) => part.includes('Sandbox:') && part.includes(' deny('))
  if (!line) return null
  const match = line.match(/Sandbox:\s+(.+?)\((\d+)\)\s+deny\(\d+\)\s+(\S+)(?:\s+(.+))?$/)
  if (!match) return null
  const [, processName, pid, operation, rawTarget = ''] = match
  const target = rawTarget.trim()
  const category = categoryForOperation(operation)
  const sensitivity = classifySandboxDenialSensitivity({ operation, target })
  return {
    backend: 'sandbox-exec',
    source: 'macos-unified-log',
    result: 'deny',
    severity: sensitivity.severity,
    sensitivity: sensitivity.sensitivity,
    sensitivityReason: sensitivity.reason,
    notificationRecommended: sensitivity.notify,
    category,
    operation,
    actor: processName.trim(),
    pid: Number(pid) || 0,
    target,
    path: category === 'filesystem' ? target : '',
    executablePath: category === 'process' ? target : '',
    ruleTag: expectedTag || '',
    logMessage: line,
  }
}

export const startSandboxDenialStream = ({
  tag,
  onDenial,
  onError,
  spawnImpl = spawn,
  platform = process.platform,
} = {}) => {
  if (platform !== 'darwin' || !tag || typeof onDenial !== 'function') {
    return { stop: () => {} }
  }

  const predicate = `eventMessage CONTAINS "${escapePredicateString(tag)}"`
  const child = spawnImpl('/usr/bin/log', ['stream', '--style', 'compact', '--predicate', predicate], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdoutBuffer = ''
  let stderrBuffer = ''
  let pendingSandboxLine = ''
  const seen = new Set()

  const handleMessage = (message) => {
    const denial = parseSandboxDenialMessage(message, tag)
    if (!denial) return
    const key = `${denial.pid}:${denial.operation}:${denial.target}:${denial.ruleTag}`
    if (seen.has(key)) return
    seen.add(key)
    if (seen.size > 1000) {
      const [oldest] = seen
      seen.delete(oldest)
    }
    onDenial(denial)
  }

  child.stdout?.on('data', (chunk) => {
    stdoutBuffer += chunk.toString('utf8')
    const lines = stdoutBuffer.split(/\r?\n/)
    stdoutBuffer = lines.pop() || ''
    for (const line of lines) {
      if (line.includes('Sandbox:') && line.includes(' deny(')) {
        pendingSandboxLine = line
        if (line.includes(tag)) handleMessage(line)
        continue
      }
      if (line.includes(tag)) {
        handleMessage(pendingSandboxLine ? `${pendingSandboxLine}\n${line}` : line)
        pendingSandboxLine = ''
      }
    }
  })

  child.stderr?.on('data', (chunk) => {
    stderrBuffer += chunk.toString('utf8')
    const lines = stderrBuffer.split(/\r?\n/)
    stderrBuffer = lines.pop() || ''
    for (const line of lines) {
      if (line.trim()) onError?.(line.trim())
    }
  })

  child.on('error', (error) => onError?.(error.message))

  return {
    child,
    stop: (graceMs = 400) =>
      new Promise((resolve) => {
        let done = false
        const finish = () => {
          if (done) return
          done = true
          resolve()
        }
        child.once('exit', finish)
        setTimeout(() => {
          if (!child.killed) child.kill('SIGTERM')
          setTimeout(finish, 200).unref()
        }, graceMs).unref()
      }),
  }
}
