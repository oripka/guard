#!/usr/bin/env node

import fs from 'node:fs'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import path from 'node:path'

const repoRoot = path.resolve(new URL('..', import.meta.url).pathname)
const distDir = path.join(repoRoot, 'dist')
const buildDir = path.join(repoRoot, '.build')
const ironProxyRepo = process.env.GUARD_IRON_PROXY_REPO || 'https://github.com/oripka/iron-proxy'
const ironProxyRef = process.env.GUARD_IRON_PROXY_REF || 'main'
const ironProxyDir = path.join(buildDir, 'iron-proxy')
const ironProxyBinDir = path.join(buildDir, 'iron-proxy-bin')
const platformArch = `${process.platform}-${process.arch}`
const packageVersion = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
    ...options,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`)
  }
}

const commandOutput = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env,
    ...options,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  }
  return String(result.stdout || '').trim()
}

const buildIronProxy = () => {
  fs.rmSync(ironProxyDir, { recursive: true, force: true })
  fs.rmSync(ironProxyBinDir, { recursive: true, force: true })
  fs.mkdirSync(buildDir, { recursive: true })
  fs.mkdirSync(ironProxyBinDir, { recursive: true })
  run('git', ['clone', '--depth', '1', '--branch', ironProxyRef, ironProxyRepo, ironProxyDir])
  const commit = commandOutput('git', ['rev-parse', 'HEAD'], { cwd: ironProxyDir })
  const output = path.join(ironProxyBinDir, `iron-proxy-${platformArch}`)
  run('go', ['build', '-trimpath', '-o', output, './cmd/iron-proxy'], { cwd: ironProxyDir })
  return {
    repo: ironProxyRepo,
    ref: ironProxyRef,
    commit,
    artifact: path.basename(output),
    path: output,
    bundledOnly: true,
  }
}

const copyInto = (root, entries) => {
  for (const entry of entries) {
    const source = path.join(repoRoot, entry)
    if (!fs.existsSync(source)) continue
    const destination = path.join(root, entry)
    fs.mkdirSync(path.dirname(destination), { recursive: true })
    fs.cpSync(source, destination, { recursive: true })
  }
}

const pruneBuildArtifacts = (root) => {
  for (const relative of [
    '.build',
    'dist',
    'native/GuardMacApp/.build',
    'native/macos-launcher/.build',
  ]) {
    fs.rmSync(path.join(root, relative), { recursive: true, force: true })
  }
}

const writeEditionMetadata = (root, edition, extra = {}) => {
  const ironProxy = extra.ironProxy
    ? {
        repo: extra.ironProxy.repo,
        ref: extra.ironProxy.ref,
        commit: extra.ironProxy.commit,
        bundledOnly: true,
      }
    : undefined
  fs.writeFileSync(
    path.join(root, 'GUARD_EDITION.json'),
    `${JSON.stringify({
      name: `guard-${edition}`,
      edition,
      version: packageVersion,
      platform: process.platform,
      arch: process.arch,
      stability: edition === 'cli' ? 'alpha' : 'experimental',
      includes: extra.includes || [],
      excludes: extra.excludes || [],
      ironProxy,
    }, null, 2)}\n`,
  )
}

const writeInstallScript = (root, edition) => {
  const script = `#!/bin/sh
set -eu

prefix="\${1:-$HOME/.local}"
bin_dir="$prefix/bin"
package_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)

mkdir -p "$bin_dir"
ln -sfn "$package_dir/bin/guard" "$bin_dir/guard"
ln -sfn "$package_dir/bin/iron-proxy" "$bin_dir/iron-proxy"

"$package_dir/bin/guard" setup --yes --bin-dir "$bin_dir" --code-root "\${GUARD_CODE_ROOT:-$HOME/code}" --force ${edition === 'cli' ? '--no-shims' : ''}

printf '%s\\n' "Guard ${edition} installed into $package_dir"
printf '%s\\n' "Add $bin_dir to PATH if it is not already present."
`
  const target = path.join(root, 'install.sh')
  fs.writeFileSync(target, script)
  fs.chmodSync(target, 0o755)
}

const writeUninstallScript = (root) => {
  const script = `#!/bin/sh
set -eu

prefix="\${GUARD_PREFIX:-$HOME/.local}"
install_root="\${GUARD_INSTALL_ROOT:-$prefix/guard}"
bin_dir="\${GUARD_BIN_DIR:-$prefix/bin}"
remove_config="\${GUARD_REMOVE_CONFIG:-0}"

remove_link_or_file() {
  name="$1"
  path="$bin_dir/$name"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    return
  fi

  if [ -L "$path" ]; then
    target=$(readlink "$path" || printf '')
    case "$target" in
      "$install_root"/*|*/guard/bin/guard|*/guard/bin/iron-proxy)
        rm -f "$path"
        printf '%s\\n' "Removed $path"
        ;;
      *)
        printf '%s\\n' "Skipped $path; it does not point into $install_root"
        ;;
    esac
  else
    printf '%s\\n' "Skipped $path; it is not a symlink"
  fi
}

for name in guard iron-proxy guard-zoom guard-teams guard-webex; do
  remove_link_or_file "$name"
done

if [ -d "$install_root" ]; then
  rm -rf "$install_root"
  printf '%s\\n' "Removed $install_root"
fi

if [ "$remove_config" = "1" ]; then
  rm -rf "$HOME/.config/guard"
  printf '%s\\n' "Removed $HOME/.config/guard"
else
  printf '%s\\n' "Kept $HOME/.config/guard"
  printf '%s\\n' "Set GUARD_REMOVE_CONFIG=1 to remove Guard config and local policy state."
fi
`
  const target = path.join(root, 'uninstall.sh')
  fs.writeFileSync(target, script)
  fs.chmodSync(target, 0o755)
}

const createTarball = (name, root) => {
  const artifact = `${name}.tar.gz`
  run('tar', ['-czf', path.join(distDir, artifact), '-C', path.dirname(root), path.basename(root)])
  return artifact
}

const findMacAppBinary = () => {
  const releaseRoot = path.join(repoRoot, 'native/GuardMacApp/.build')
  if (!fs.existsSync(releaseRoot)) return ''
  const candidates = []
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(fullPath)
      } else if (entry.name === 'GuardMacApp' && fullPath.includes(`${path.sep}release${path.sep}`)) {
        candidates.push(fullPath)
      }
    }
  }
  walk(releaseRoot)
  return candidates.sort()[0] || ''
}

const createEdition = ({ edition, entries, ironProxy, extra = {} }) => {
  const name = `guard-${edition}-${packageVersion}-${platformArch}`
  const root = path.join(buildDir, 'packages', name)
  fs.rmSync(root, { recursive: true, force: true })
  fs.mkdirSync(root, { recursive: true })
  copyInto(root, entries)
  pruneBuildArtifacts(root)
  const binDir = path.join(root, 'bin')
  fs.mkdirSync(binDir, { recursive: true })
  fs.copyFileSync(ironProxy.path, path.join(binDir, 'iron-proxy'))
  fs.chmodSync(path.join(binDir, 'iron-proxy'), 0o755)
  writeInstallScript(root, edition)
  writeUninstallScript(root)
  writeEditionMetadata(root, edition, {
    ...extra,
    ironProxy,
  })
  return createTarball(name, root)
}

const createEditions = ({ ironProxy, macAppBuilt }) => {
  const common = [
    'bin',
    'docs',
    'lib',
    'profiles',
    'templates',
    'uninstall.sh',
    'AGENTS.md',
    'LICENSE',
    'README.md',
    'package.json',
  ]
  const artifacts = [
    createEdition({
      edition: 'cli',
      entries: common,
      ironProxy,
      extra: {
        includes: ['guard CLI', 'profile templates', 'iron-proxy binary'],
        excludes: ['guardd daemon', 'native macOS UI sources and app binary'],
      },
    }),
    createEdition({
      edition: 'daemon',
      entries: [...common, 'daemon'],
      ironProxy,
      extra: {
        includes: ['guard CLI', 'guardd daemon', 'profile templates', 'iron-proxy binary'],
        excludes: ['native macOS UI sources and app binary'],
      },
    }),
  ]

  if (process.platform === 'darwin' && macAppBuilt) {
    const artifact = createEdition({
      edition: 'desktop',
      entries: [...common, 'daemon', 'native'],
      ironProxy,
      extra: {
        includes: ['guard CLI', 'guardd daemon', 'native macOS UI sources', 'GuardMacApp binary', 'iron-proxy binary'],
        excludes: [],
      },
    })
    const desktopRoot = path.join(
      buildDir,
      'packages',
      `guard-desktop-${packageVersion}-${platformArch}`,
    )
    const appBinary = findMacAppBinary()
    const appDestination = path.join(desktopRoot, 'native/GuardMacApp/bin/GuardMacApp')
    if (fs.existsSync(appBinary)) {
      fs.mkdirSync(path.dirname(appDestination), { recursive: true })
      fs.copyFileSync(appBinary, appDestination)
      fs.chmodSync(appDestination, 0o755)
      fs.rmSync(path.join(distDir, artifact), { force: true })
      artifacts.push(createTarball(`guard-desktop-${packageVersion}-${platformArch}`, desktopRoot))
    } else {
      artifacts.push(artifact)
    }
  }

  return artifacts
}

fs.rmSync(distDir, { recursive: true, force: true })
fs.mkdirSync(distDir, { recursive: true })

const ironProxy = buildIronProxy()

run('npm', ['pack', '--pack-destination', distDir])

let macAppBuilt = false
if (process.platform === 'darwin') {
  run('swift', ['build', '--package-path', 'native/GuardMacApp', '-c', 'release'])
  macAppBuilt = true
}

const editionArtifacts = createEditions({ ironProxy, macAppBuilt })
const ironProxyMetadata = {
  repo: ironProxy.repo,
  ref: ironProxy.ref,
  commit: ironProxy.commit,
  bundledIntoEditions: true,
}

const manifest = {
  package: 'guard',
  stability: 'alpha',
  platform: process.platform,
  artifacts: fs.readdirSync(distDir).sort(),
  editions: editionArtifacts,
  ironProxy: ironProxyMetadata,
  nativeMacAppBuilt: macAppBuilt,
  daemonExperimental: true,
  desktopExperimental: true,
  linuxBubblewrapBackend: process.platform === 'linux',
}

fs.writeFileSync(path.join(distDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)

const checksumLines = fs.readdirSync(distDir)
  .filter((name) => name !== 'SHA256SUMS')
  .sort()
  .map((name) => {
    const hash = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(distDir, name)))
      .digest('hex')
    return `${hash}  ${name}`
  })
fs.writeFileSync(path.join(distDir, 'SHA256SUMS'), `${checksumLines.join('\n')}\n`)
