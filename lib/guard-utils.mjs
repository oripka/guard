import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const containsGlobChars = (value) => /[*?[\]]/.test(value)

export const globToRegex = (globPattern) =>
  '^' +
  globPattern
    .replace(/[.^$+{}()|\\]/g, '\\$&')
    .replace(/\[([^\]]*?)$/g, '\\[$1')
    .replace(/\*\*\//g, '__GLOBSTAR_SLASH__')
    .replace(/\*\*/g, '__GLOBSTAR__')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/__GLOBSTAR_SLASH__/g, '(.*/)?')
    .replace(/__GLOBSTAR__/g, '.*') +
  '$'

export const escapeSeatbelt = (value) => JSON.stringify(value)

export const getAncestorDirectories = (pathStr) => {
  const ancestors = []
  let currentPath = path.dirname(pathStr)
  while (currentPath !== '/' && currentPath !== '.') {
    ancestors.push(currentPath)
    const parentPath = path.dirname(currentPath)
    if (parentPath === currentPath) break
    currentPath = parentPath
  }
  return ancestors
}

export const isSymlinkOutsideBoundary = (originalPath, resolvedPath) => {
  const normalizedOriginal = path.normalize(originalPath)
  const normalizedResolved = path.normalize(resolvedPath)

  if (normalizedResolved === normalizedOriginal) return false
  if (
    normalizedOriginal.startsWith('/tmp/') &&
    normalizedResolved === `/private${normalizedOriginal}`
  ) {
    return false
  }
  if (
    normalizedOriginal.startsWith('/var/') &&
    normalizedResolved === `/private${normalizedOriginal}`
  ) {
    return false
  }
  if (normalizedResolved === '/') return true

  const resolvedParts = normalizedResolved.split('/').filter(Boolean)
  if (resolvedParts.length <= 1) return true
  if (normalizedOriginal.startsWith(`${normalizedResolved}/`)) return true

  let canonicalOriginal = normalizedOriginal
  if (normalizedOriginal.startsWith('/tmp/')) {
    canonicalOriginal = `/private${normalizedOriginal}`
  } else if (normalizedOriginal.startsWith('/var/')) {
    canonicalOriginal = `/private${normalizedOriginal}`
  }

  if (
    canonicalOriginal !== normalizedOriginal &&
    canonicalOriginal.startsWith(`${normalizedResolved}/`)
  ) {
    return true
  }

  const resolvedStartsWithOriginal = normalizedResolved.startsWith(
    `${normalizedOriginal}/`,
  )
  const resolvedStartsWithCanonical =
    canonicalOriginal !== normalizedOriginal &&
    normalizedResolved.startsWith(`${canonicalOriginal}/`)
  const resolvedIsCanonical =
    canonicalOriginal !== normalizedOriginal &&
    normalizedResolved === canonicalOriginal

  return !(
    resolvedIsCanonical ||
    resolvedStartsWithOriginal ||
    resolvedStartsWithCanonical
  )
}

export const normalizePathForSandbox = (pathPattern, cwd) => {
  let normalizedPath = pathPattern

  if (pathPattern === '~') {
    normalizedPath = os.homedir()
  } else if (pathPattern.startsWith('~/')) {
    normalizedPath = os.homedir() + pathPattern.slice(1)
  } else if (pathPattern.startsWith('./') || pathPattern.startsWith('../')) {
    normalizedPath = path.resolve(cwd, pathPattern)
  } else if (!path.isAbsolute(pathPattern)) {
    normalizedPath = path.resolve(cwd, pathPattern)
  }

  if (containsGlobChars(normalizedPath)) {
    const staticPrefix = normalizedPath.split(/[*?[\]]/)[0]
    if (staticPrefix && staticPrefix !== '/') {
      const baseDir = staticPrefix.endsWith('/')
        ? staticPrefix.slice(0, -1)
        : path.dirname(staticPrefix)
      try {
        const resolvedBaseDir = fs.realpathSync(baseDir)
        if (!isSymlinkOutsideBoundary(baseDir, resolvedBaseDir)) {
          return resolvedBaseDir + normalizedPath.slice(baseDir.length)
        }
      } catch {}
    }
    return normalizedPath
  }

  try {
    const resolvedPath = fs.realpathSync(normalizedPath)
    if (!isSymlinkOutsideBoundary(normalizedPath, resolvedPath)) {
      normalizedPath = resolvedPath
    }
  } catch {}

  return normalizedPath
}

export const emitPathRule = (
  effect,
  operation,
  pathPattern,
  message,
  cwd,
) => {
  const normalizedPath = normalizePathForSandbox(pathPattern, cwd)
  if (containsGlobChars(normalizedPath)) {
    return [
      `(${effect} ${operation}`,
      `  (regex ${escapeSeatbelt(globToRegex(normalizedPath))})`,
      `  (with message ${escapeSeatbelt(message)}))`,
    ]
  }
  return [
    `(${effect} ${operation}`,
    `  (subpath ${escapeSeatbelt(normalizedPath)})`,
    `  (with message ${escapeSeatbelt(message)}))`,
  ]
}

export const emitNameRule = (
  effect,
  operation,
  matcher,
  value,
) => {
  const supportsPrefix = matcher.endsWith('name')
  if (supportsPrefix && value.endsWith('*')) {
    return `(${effect} ${operation} (${matcher}-prefix ${escapeSeatbelt(value.slice(0, -1))}))`
  }
  return `(${effect} ${operation} (${matcher} ${escapeSeatbelt(value)}))`
}

export const generateMoveBlockingRules = (pathPatterns, logTag, cwd) => {
  const rules = []
  for (const pathPattern of pathPatterns) {
    const normalizedPath = normalizePathForSandbox(pathPattern, cwd)
    if (containsGlobChars(normalizedPath)) {
      rules.push(
        '(deny file-write-unlink',
        `  (regex ${escapeSeatbelt(globToRegex(normalizedPath))})`,
        `  (with message ${escapeSeatbelt(logTag)}))`,
      )

      const staticPrefix = normalizedPath.split(/[*?[\]]/)[0]
      if (staticPrefix && staticPrefix !== '/') {
        const baseDir = staticPrefix.endsWith('/')
          ? staticPrefix.slice(0, -1)
          : path.dirname(staticPrefix)
        rules.push(
          '(deny file-write-unlink',
          `  (literal ${escapeSeatbelt(baseDir)})`,
          `  (with message ${escapeSeatbelt(logTag)}))`,
        )
        for (const ancestorDir of getAncestorDirectories(baseDir)) {
          rules.push(
            '(deny file-write-unlink',
            `  (literal ${escapeSeatbelt(ancestorDir)})`,
            `  (with message ${escapeSeatbelt(logTag)}))`,
          )
        }
      }
      continue
    }

    rules.push(
      '(deny file-write-unlink',
      `  (subpath ${escapeSeatbelt(normalizedPath)})`,
      `  (with message ${escapeSeatbelt(logTag)}))`,
    )
    for (const ancestorDir of getAncestorDirectories(normalizedPath)) {
      rules.push(
        '(deny file-write-unlink',
        `  (literal ${escapeSeatbelt(ancestorDir)})`,
        `  (with message ${escapeSeatbelt(logTag)}))`,
      )
    }
  }
  return rules
}
