# Supply Chain Policy

Guard's supply-chain policy protects package install workflows in three layers:

1. Threat intelligence blocks known-bad package versions before the artifact is
   downloaded.
2. Dependency cooldown filters newly-published versions from registry metadata
   so package managers resolve to older eligible versions.
3. Install sandboxing narrows filesystem, subprocess, and network permissions
   for package-manager install/download commands.

These layers are part of the simple per-run Guard path. They do not require
`guardd`, Guard.app, a Network Extension, or a long-running daemon. Daemon/UI
mode can later use the same policy shape for richer prompts, persistent rule
management, and review history.

## Quick Start

Enable the default install sandbox:

```json
{
  "supplyChain": {
    "installSandbox": true
  }
}
```

Enable all checked-in package policy layers:

```json
{
  "supplyChain": {
    "installHardening": true,
    "installSandbox": true,
    "dependencyCooldown": {
      "enabled": true,
      "days": 5
    },
    "threatIntelligence": {
      "blockedPackages": [
        "pkg:npm/safedep-test-pkg@1.0.0"
      ],
      "blockPackageLookupAlerts": true,
      "promptOnBlock": true
    },
    "sanitizeEnvironment": true
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

Force the install sandbox for one command:

```sh
guard --install-sandbox pnpm install
```

Add a one-run exception:

```sh
guard --install-sandbox \
  --install-sandbox-allow write=./.npmrc \
  --install-sandbox-allow domain=registry.npmjs.org \
  pnpm install
```

## Layer 1: Threat Intelligence

`supplyChain.threatIntelligence` evaluates detected package artifact downloads
before forwarding the request upstream. When an interactive run finds a known
threat-intelligence block candidate, Guard opens the same native prompt surface
used for network decisions and asks whether to deny or allow that one download.
Deny is the default. Non-interactive runs deny without prompting. Packages with
no known finding do not prompt.

Current implementation:

- local deny lists through `blockedPackages`, `blockedPurls`,
  `deniedPackages`, or `maliciousPackages`
- optional Socket Firewall lookup results from `supplyChain.packageLookup`
- an optional HTTP adapter endpoint with the same decision contract
- Guard events for allowed, blocked, and lookup-error outcomes

Example:

```json
{
  "supplyChain": {
    "threatIntelligence": {
      "blockedPackages": [
        "pkg:npm/evil-package@1.2.3",
        "pkg:pypi/typosquat-demo@0.0.4"
      ]
    }
  }
}
```

Optional adapter endpoint:

```json
{
  "supplyChain": {
    "threatIntelligence": {
      "enabled": true,
      "endpoint": "http://127.0.0.1:7777/package-analysis",
      "apiKeyEnv": "SAFEDEP_API_KEY",
      "timeoutMs": 5000,
      "failClosed": true,
      "blockSuspicious": true
    }
  }
}
```

Optional Socket Firewall lookup:

```json
{
  "supplyChain": {
    "packageLookup": {
      "provider": "socket-free",
      "ttlMs": 3600000,
      "timeoutMs": 5000
    },
    "threatIntelligence": {
      "enabled": true,
      "blockPackageLookupAlerts": true,
      "promptOnBlock": true
    }
  }
}
```

`packageLookup.provider: "socket-free"` calls Socket's free PURL lookup API and
records the result on `package-fetch` events as `packageLookup`. By default this
is observe-only. Set `threatIntelligence.blockPackageLookupAlerts: true` when
Socket lookup alerts should become blocking threat-intelligence decisions. This
keeps existing SFW telemetry behavior compatible with stricter profiles. With
`promptOnBlock` enabled, those blocking lookup alerts ask the user by default in
interactive Guard runs.

The lookup provider can also be enabled for one run with:

```sh
GUARD_PACKAGE_LOOKUP_PROVIDER=socket-free guard pnpm install
```

The endpoint receives a JSON package object:

```json
{
  "ecosystem": "npm",
  "name": "fixture",
  "version": "1.0.0",
  "purl": "pkg:npm/fixture@1.0.0"
}
```

It should return JSON. Any of these shapes blocks the package:

```json
{
  "action": "block",
  "summary": "Verified malicious package",
  "referenceUrl": "https://example.invalid/report"
}
```

```json
{
  "isMalware": true,
  "isVerified": true,
  "summary": "Verified malicious package"
}
```

Suspicious-only results block when `blockSuspicious` is true:

```json
{
  "action": "confirm",
  "suspicious": true,
  "summary": "Suspicious install script"
}
```

SafeDep PMG uses SafeDep Malysis over gRPC. Guard does not yet include a native
Malysis gRPC client. The adapter shape above is deliberate: a local SafeDep
adapter can translate Malysis results to Guard decisions without changing Guard
profiles, events, or UI copy.

### Threat-Intel Events

Guard writes these event types to the normal Guard event log:

- `supply_chain.package_policy.enabled`
- `supply_chain.threat_intel.allowed`
- `supply_chain.threat_intel.blocked`
- `supply_chain.threat_intel.error`

The built-in proxy also emits network flow phases:

- `package-fetch`
- `package-blocked`

`package-fetch` includes `packageLookup` when SFW lookup is enabled. If
`blockPackageLookupAlerts` is true and the lookup returns a blocking alert, the
same request also emits `package-blocked` and receives a `403`.

## Optional Socket PURL Lookup

`network.packageLookup.provider: "socket-free"` enables the undocumented free
Socket endpoint observed in `sfw-free`:

```text
GET https://firewall-api.socket.dev/purl/[encodedPurl]
```

Guard builds a package URL such as `pkg:npm/lodash@4.17.21`, URL-encodes it
into the path, parses the newline-delimited JSON response, and attaches the
result to `package-fetch` network events.

Example:

```json
{
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

Environment overrides:

- `GUARD_PACKAGE_LOOKUP_PROVIDER=socket-free`
- `GUARD_PACKAGE_LOOKUP_TTL_MS=3600000`
- `GUARD_PACKAGE_LOOKUP_TIMEOUT_MS=5000`

The lookup cache is per guarded run, keyed by PURL, with in-flight request
deduplication. The default TTL is one hour so repeated registry downloads do not
flood the free endpoint, while stale intelligence naturally refreshes during
longer sessions.

This provider is observe-only by default. The endpoint is undocumented and its
response schema is not a stable Guard contract. Use
`supplyChain.threatIntelligence.blockedPackages`, `blockedPurls`,
`blockPackageLookupAlerts: true`, or a threat-intelligence adapter endpoint for
blocking decisions. When enabled, the policy banner prints a package segment
such as:

```text
pkg install-sandbox blocklist cooldown=5d lookup=socket-free cache=60m observe
```

When lookup alerts are configured to block, the same segment ends with
`cache=60m block`.

## Layer 2: Dependency Cooldown

`supplyChain.dependencyCooldown` blocks package versions published inside a
configurable age window. For registry metadata requests, Guard strips too-new
versions before the package manager sees them. If the requested range allows an
older version, the resolver naturally falls back. If no eligible version
remains, the package manager fails.

Example:

```json
{
  "supplyChain": {
    "dependencyCooldown": {
      "enabled": true,
      "days": 5
    }
  }
}
```

Guard currently filters:

- npm package metadata from `registry.npmjs.org`
- PyPI PEP 691 JSON Simple API responses from `pypi.org/simple/<package>/`

For npm, Guard forces a full packument by changing request headers:

- `Accept: application/json`
- `Accept-Encoding: identity`

It also removes conditional request headers so the registry returns a full body
instead of `304 Not Modified`.

For PyPI, Guard requests PEP 691 JSON metadata:

- `Accept: application/vnd.pypi.simple.v1+json`
- `Accept-Encoding: identity`

Guard removes filtered npm versions from:

- `versions`
- `time`
- `dist-tags`

If a dist-tag points at a filtered version, Guard rewrites it to the newest
eligible version. If none exists, the tag is removed.

Guard removes filtered PyPI entries from:

- `files`

### Cooldown Events

Guard writes these event types:

- `supply_chain.dependency_cooldown.filtered`
- `supply_chain.dependency_cooldown.blocked`

`filtered` means metadata was rewritten. `blocked` means Guard had an exact
artifact publish date from policy data and blocked the artifact download itself.

### Cooldown Boundaries

Cooldown metadata filtering requires an HTTP-aware proxy path. It does not
protect traffic that bypasses Guard's proxy environment. The per-run sandbox
should still block direct raw egress for package managers that are expected to
use the proxy.

The checked-in response rewriting is implemented in Guard's built-in HTTP proxy.
The default `iron-proxy` backend currently enforces request-stage package
blocking and SFW lookup through Guard's interactive policy server, but full
response-stage metadata rewriting still needs a dedicated `iron-proxy`
transform.

Direct tarball URLs and lockfile/cache paths may skip version-resolution
metadata. Guard can still block known-bad tarballs through threat-intel artifact
blocking when the artifact URL is visible.

## Layer 3: Install Sandbox

`supplyChain.installSandbox` applies a narrower policy to package-manager
install/download commands. It keeps normal commands such as `pnpm run dev` on
the profile's regular filesystem policy.

Example:

```json
{
  "supplyChain": {
    "installSandbox": {
      "enabled": true,
      "enforceAlways": false
    }
  }
}
```

Guard currently recognizes install/download workflows for:

- `npm`
- `pnpm`
- `yarn`
- `bun`
- `npx`
- `pnpx`
- `pip`
- `pip3`
- `uv`
- `poetry`

Node install commands can write common package artifacts:

- `node_modules`
- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `bun.lock`
- `.pnpm-store`

Python install commands can write common package artifacts:

- `.venv`
- `venv`
- `pyproject.toml`
- `uv.lock`
- `poetry.lock`
- `requirements.txt`
- `requirements-*.txt`

The sandbox always permits Guard's per-run home and temp directories. It removes
broad project write grants for install commands unless
`keepProfileWrites: true` is set.

### Mandatory Secret Denies

The install sandbox adds read/write deny rules for common credentials and
persistence points, including:

- `.env`
- `.aws`
- `.azure`
- `.gcloud`
- `.config/gcloud`
- `.kube`
- `.ssh`
- `.gnupg`
- `.docker/config.json`
- `.netrc`
- `.git-credentials`
- `.pgpass`
- `.config/gh`
- `.npmrc`
- `.pypirc`
- `.cargo/credentials`
- `.gem/credentials`
- `.git/hooks`

Read denies are emitted after broad allow rules through
`filesystem.denyReadAfterAllow`, so a profile can still allow the project tree
while hiding project-local secrets from install scripts.

Use explicit exceptions only when the workflow requires them:

```json
{
  "supplyChain": {
    "installSandbox": {
      "allowRead": ["${GUARD_PROJECT_DIR}/.npmrc"],
      "allowWrite": ["${GUARD_PROJECT_DIR}/node_modules/.cache"],
      "allowExec": ["${GUARD_PROJECT_DIR}/scripts/postinstall-safe.sh"],
      "allowGitConfig": false
    }
  }
}
```

One-run exceptions use `--install-sandbox-allow`:

```sh
guard --install-sandbox-allow read=./.npmrc pnpm install
guard --install-sandbox-allow write=./node_modules/.cache pnpm install
guard --install-sandbox-allow exec=./scripts/postinstall-safe.sh pnpm install
guard --install-sandbox-allow domain=registry.npmjs.org pnpm install
guard --install-sandbox-allow net=localhost:8976 pnpm install
```

Supported one-run exception types:

- `read=PATH`
- `write=PATH`
- `exec=PATH`
- `domain=HOST`
- `net=HOST[:PORT]`
- `net-connect=HOST[:PORT]`
- `net-bind=HOST:PORT`

External `net` exceptions become proxied domain allows. Loopback `host:port`
exceptions become exact loopback port allows.

### Install Sandbox Events

Guard writes:

- `supply_chain.install_sandbox`

The event includes the detected package manager, whether the command matched an
install pattern, whether the policy was forced, and the one-run/profile
exceptions that were applied.

## `installHardening`

`installHardening` is separate from `installSandbox`. It adds package-install
oriented defaults that are useful even when the filesystem sandbox is not
active:

- deny writes to common persistence paths
- block risky child executables such as `curl`, `wget`, `python`, `ruby`,
  `perl`, `osascript`, and `nc`
- inject package-manager environment settings such as
  `NPM_CONFIG_IGNORE_SCRIPTS=true`
- clear the inherited environment unless `sanitizeEnvironment` is false

Example:

```json
{
  "supplyChain": {
    "installHardening": true,
    "sanitizeEnvironment": true
  }
}
```

## Recommended Profiles

For routine Node development:

```json
{
  "imports": ["node-app-defaults"],
  "supplyChain": {
    "installSandbox": true,
    "dependencyCooldown": {
      "enabled": true,
      "days": 5
    }
  }
}
```

For high-risk dependency review:

```json
{
  "imports": ["node-app-defaults"],
  "supplyChain": {
    "installHardening": true,
    "installSandbox": {
      "enabled": true,
      "enforceAlways": true
    },
    "dependencyCooldown": {
      "enabled": true,
      "days": 7
    },
    "threatIntelligence": {
      "enabled": true,
      "endpoint": "http://127.0.0.1:7777/package-analysis",
      "failClosed": true,
      "blockSuspicious": true
    },
    "sanitizeEnvironment": true
  },
  "process": {
    "denyByDefault": true
  }
}
```

## Limitations

- Guard's direct SafeDep Malysis client is not implemented yet. Use the HTTP
  adapter contract or local PURL blocklists until that exists.
- Cooldown metadata rewriting is currently in Guard's built-in HTTP proxy, not
  in `iron-proxy` response transforms.
- PyPI cooldown requires clients that request or accept PEP 691 JSON metadata.
  Older HTML-only clients cannot provide upload timestamps for filtering.
- Direct raw egress bypasses proxy-level package policy. Keep direct egress
  blocked in per-run profiles unless there is a narrow reviewed exception.
- Lockfile-only or cache-hit installs may not request metadata. Threat-intel
  artifact blocking still applies when Guard sees the artifact download.
