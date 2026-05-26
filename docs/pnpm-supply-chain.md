# pnpm and Supply-Chain Installs

This feature protects dependency installation, especially packages that try to
run code during `preinstall`, `install`, `postinstall`, or `prepare`.

## Benefit

Package install scripts are a common supply-chain execution path. A dependency
can download a payload, read credentials, write persistence files, or make
network requests before application code ever runs. Guard reduces that risk by
combining package-manager settings, filesystem sandboxing, subprocess policy,
network policy, threat intelligence, and lifecycle-script auditing.

## Defaults

The `node-app-defaults` import enables:

- `supplyChain.installSandbox`: narrow package-install filesystem writes.
- `supplyChain.installHardening`: injected package-manager hardening defaults.
- lifecycle-script scanning for Node installs.
- pnpm unsafe build-setting rejection.
- npm registry allow by default.
- optional package lookup and threat-intelligence blocking.

Guard injects these install hardening variables for guarded installs:

```sh
NPM_CONFIG_IGNORE_SCRIPTS=true
npm_config_ignore_scripts=true
PNPM_CONFIG_IGNORE_SCRIPTS=true
pnpm_config_ignore_scripts=true
PNPM_IGNORE_SCRIPTS=true
YARN_ENABLE_SCRIPTS=false
```

That blocks install-time lifecycle execution even if the project accidentally
configures a permissive package-manager setting.

## Project Config

Use the shared Node defaults:

```json
{
  "imports": ["node-app-defaults"]
}
```

Or configure the supply-chain layer explicitly:

```json
{
  "supplyChain": {
    "installSandbox": {
      "enabled": true,
      "enforceAlways": false
    },
    "lifecycleScripts": {
      "enabled": true,
      "scanNodeModules": true,
      "blockUnsafePnpmConfig": true
    },
    "threatIntelligence": {
      "enabled": true,
      "blockPackageLookupAlerts": true,
      "promptOnBlock": true
    }
  },
  "network": {
    "allowedDomains": ["registry.npmjs.org"],
    "packageLookup": {
      "provider": "socket-free",
      "ttlMs": 3600000,
      "timeoutMs": 5000
    }
  }
}
```

Run:

```sh
guard pnpm install
guard --install-sandbox pnpm install
guard scan npm --include-node-modules --lifecycle
```

## pnpm Build Settings

pnpm 11 uses `allowBuilds` in `pnpm-workspace.yaml` for explicit package build
approval. Packages not listed are disallowed by default and, with
`strictDepBuilds: true`, unreviewed build scripts fail the install.

Recommended project settings:

```yaml
minimumReleaseAge: 1440
minimumReleaseAgeStrict: true
blockExoticSubdeps: true
strictDepBuilds: true
dangerouslyAllowAllBuilds: false
allowBuilds:
  esbuild: true
  sharp: true
  core-js: false
```

Guard blocks guarded pnpm installs when `pnpm-workspace.yaml` contains:

```yaml
dangerouslyAllowAllBuilds: true
```

Use `pnpm approve-builds` when a dependency legitimately needs an install-time
build. Review each package and commit the resulting `allowBuilds` entries.

pnpm references:

- [Settings: allowBuilds and strictDepBuilds](https://pnpm.io/settings#allowbuilds)
- [pnpm approve-builds](https://pnpm.io/cli/approve-builds)

## What It Protects

Guard protects against:

- dependency lifecycle scripts reading project or home secrets.
- lifecycle scripts writing Git hooks, shell startup files, or package tokens.
- package manager subprocesses invoking common stagers such as `curl`, `wget`,
  `gh`, `git`, Python, Ruby, Perl, `osascript`, or `nc`.
- new or suspicious packages resolved through configured package lookup.
- very new dependency versions when release-age gates are configured.
- direct raw network bypass when the per-run sandbox backend can block it.

## Global Defaults

Guard global setup lives under `~/.config/guard/config.json` and records the
managed code root and shim install directory. Environment overrides include:

```sh
GUARD_CODE_ROOT=~/code
GUARD_PACKAGE_LOOKUP_PROVIDER=socket-free
GUARD_PACKAGE_LOOKUP_TTL_MS=3600000
GUARD_STATE_DIR=~/Library/Application\ Support/guard
```

pnpm global settings live in `~/.config/pnpm/config.yaml`. Prefer project-local
`pnpm-workspace.yaml` for supply-chain policy so the reviewed defaults travel
with the repo.

## Exceptions

Use one-run exceptions for narrow install needs:

```sh
guard --install-sandbox-allow read=./.npmrc pnpm install
guard --install-sandbox-allow write=./node_modules/.cache pnpm install
guard --install-sandbox-allow exec=./scripts/postinstall-safe.sh pnpm install
guard --install-sandbox-allow domain=registry.npmjs.org pnpm install
guard --install-sandbox-allow net=localhost:8976 pnpm install
```

Avoid broad exceptions. If a package needs lifecycle execution, approve only
that package through pnpm `allowBuilds` and keep Guard's install sandbox active.
