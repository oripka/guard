# Node App Guard Policy

Use this profile shape for local Node, Nuxt, Vite, Slidev, Wrangler, and similar
developer workflows.

This policy is intentionally fail-closed for user data and mounted volumes:

- all reads under `/Users` are denied by default
- all reads under `/Volumes` are denied by default
- common nonessential roots such as `/Applications`, `/cores`, and `/home` are
  denied by default
- only paths listed in `allowRead` are reopened

Do not create project configs with empty `denyRead` or broad home/volume reads.
See [supply-chain-policy.md](supply-chain-policy.md) for the detailed package
threat-intelligence, dependency cooldown, install sandbox, and install
hardening reference.

```json
{
  "imports": ["node-app-defaults"]
}
```

The imported default expands to:

```json
{
  "allowPty": true,
  "network": {
    "ask": false,
    "allowedDomains": [],
    "deniedDomains": [],
    "allowLocalBinding": true,
    "allowLoopbackConnections": false,
    "allowLoopbackListeningHighPorts": [],
    "allowLoopbackPorts": [
      3000,
      3001,
      4983
    ],
    "allowUnixSockets": [
      "${GUARD_RUN_DIR}"
    ],
    "allowMachLookup": [
      "com.apple.FSEvents",
      "com.apple.fseventsd",
      "com.apple.FileCoordination"
    ]
  },
  "filesystem": {
    "denyRead": [
      "/Users",
      "/Volumes",
      "/Applications",
      "/cores",
      "/home"
    ],
    "allowRead": [
      "${GUARD_PROJECT_DIR}",
      "${GUARD_RUN_DIR}"
    ],
    "allowWrite": [
      "${GUARD_PROJECT_DIR}",
      "${GUARD_RUN_DIR}"
    ],
    "denyWrite": [
      ".env",
      ".env.*",
      "secrets/",
      "*.key",
      "*.pem"
    ]
  }
}
```

Wrangler/Nitro projects that deploy to Cloudflare can start from:

```sh
guard init cloudflare-wrangler
```

That template imports `node-app-defaults` and `cloudflare-wrangler`. The
Cloudflare import adds `api.cloudflare.com`, `*.cloudflare.com`,
`*.workers.dev`, `*.pages.dev`, local dev ports `8787` and `8788`, and
Wrangler OAuth callback port `8976`. It also links the real
`~/Library/Preferences/.wrangler/config` directory into Guard's fake home so
Wrangler can reuse and refresh an existing OAuth login.

Prefer `CLOUDFLARE_API_TOKEN` for CI or repeatable non-interactive deploys.

## Child Process Policy

For dependency installation or unknown package review, enable:

```json
{
  "supplyChain": {
    "installHardening": true,
    "installSandbox": true,
    "dependencyCooldown": { "enabled": true, "days": 5 },
    "threatIntelligence": {
      "blockedPackages": ["pkg:npm/safedep-test-pkg@1.0.0"]
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

`installHardening` adds package-install oriented default denies for common stagers and
persistence paths: shells, `curl`/`wget`, `gh`, `git`, package-manager
subprocesses, Python/Ruby/Perl helpers, `.github/workflows`, Git hooks, shell
startup files, package credentials, and Python `.pth` startup files. Guard also
injects package-manager environment defaults such as
`NPM_CONFIG_IGNORE_SCRIPTS=true` and clears the inherited environment unless
`supplyChain.sanitizeEnvironment` is set to `false`.

`installSandbox` adds a PMG-style installation sandbox for package-manager
install/download commands. It keeps normal `pnpm run dev` style commands on the
profile's regular filesystem policy, but narrows install writes to package
artifacts such as `node_modules`, lockfiles, project virtualenvs, and Guard's
per-run home/temp directories. It also adds read denies for project and home
credential files after broad project read grants, so install scripts cannot read
`.env`, SSH keys, cloud credentials, package tokens, Git hooks, or similar
sensitive files. Use `--install-sandbox` to force it for one run and
`--install-sandbox-allow read=PATH|write=PATH|exec=PATH|domain=HOST` for a
non-persistent exception.

`threatIntelligence` blocks matching package PURLs before artifact download.
Today this is wired through local block lists or an HTTP adapter endpoint, so a
SafeDep Malysis adapter can be added without changing Guard's rule shape. Socket
Firewall lookup can also feed this layer when `supplyChain.packageLookup` uses
`provider: "socket-free"` and `blockPackageLookupAlerts` is enabled.
`dependencyCooldown` filters npm and PyPI registry metadata in the built-in
Guard proxy, removing versions published inside the configured cooldown window.
`network.packageLookup.provider: "socket-free"` enables the undocumented free
Socket package-URL lookup endpoint for artifact downloads. Guard sends the PURL,
caches the NDJSON result for one hour by default, and attaches it to
`package-fetch` events without using it as an automatic deny rule. Use
`threatIntelligence.blockedPackages`, `blockPackageLookupAlerts: true`, or a
threat-intelligence adapter when a package should be blocked deterministically.

For pnpm, run installs as:

```sh
guard pnpm install
```

After `guard setup` or `guard install` installs shims, a plain `pnpm install`
inside the managed code root goes through Guard automatically. The policy banner
prints a `pkg ...` segment so the run is visibly using the install sandbox,
blocklist/cooldown policy, and any observe-only Socket lookup cache.

Add `process.denyByDefault` when a project should only launch the initial
command plus a reviewed set of child processes. Add
`process.allowedExecutables` for the extra helpers, interpreters, and
project-local tools the command may spawn. The list is path based and supports
globs. If both fields are omitted, Guard keeps the default `sandbox-exec`
behavior and allows process exec. When child-process deny mode is active, Guard
automatically includes `/usr/bin/env` and the launched command, then only allows
the listed executable paths.

Include interpreters explicitly. A shell script needs `/bin/sh` or its shebang
interpreter, and a Node project normally needs the real Node binary plus any
project-local tools under `node_modules/.bin`.

## Why These Defaults

- `denyRead` blocks all user home directories, mounted external/network/vault
  volumes, and common nonessential roots by default. This is the core
  fail-closed rule.
- `allowRead` re-opens only the project root and the per-run directory that
  `guard` creates.
- `allowWrite` allows project output plus the controlled per-run guard
  directory.
- `denyWrite` protects common secret file names even inside an otherwise writable
  project.
- `allowLocalBinding` lets dev servers bind loopback localhost ports.
- `allowLoopbackPorts` lets worker/dev-server helpers connect back to exact
  localhost ports without granting external raw TCP egress. These rules are
  port-specific, not process-specific, so only list ports that are stable and
  expected for the project.
- `allowLoopbackListeningHighPorts` snapshots high loopback ports that are
  already listening when Guard starts and adds only those exact ports to the
  sandbox. Set it to `true` for all loopback-only high-port listeners, or to an
  array such as `["node", "workerd"]` to include only those lsof command names.
  This is useful for helper services that pick an ephemeral callback port before
  a guarded command launches.
- `allowLoopbackConnections` allows all localhost TCP ports and should stay an
  escape hatch for tools that cannot be pinned to exact ports.
- `allowPty` lets interactive dev CLIs use terminal raw mode for shortcuts.
- `allowMachLookup` allows macOS file watching for Vite/Nuxt/Slidev.
- `guard` also allows the narrow sysctl reads that Node's macOS FSEvents
  integration needs, such as CPU/page-size/OS-variant lookups. Projects do not
  need to add these in their own profile.

Guard intentionally does not provide a blanket "high loopback ports" option.
macOS sandbox profiles do not have a compact port-range predicate, and allowing
all high localhost ports is broad enough to be misleading. Use exact
`allowLoopbackPorts` first, then `allowLoopbackListeningHighPorts` for helper
services that are already listening before Guard launches the command.

- `allowUnixSockets` is limited to the same per-run guard directory so
  Nitro/Miniflare-style worker sockets can work without opening arbitrary Unix
  socket access.

## Guard Placeholders

`guard` resolves these placeholders before generating the native sandbox
profile:

- `${GUARD_PROJECT_DIR}`: directory containing the matched `.guard/` folder
- `${GUARD_CWD}`: directory where `guard` was invoked
- `${GUARD_RUN_DIR}`: per-config/per-working-directory runtime root
- `${GUARD_HOME_DIR}`: fake home directory inside the runtime root
- `${GUARD_TMP_DIR}`: temp directory inside the runtime root

## When A Project Needs More

Add the narrowest explicit path. Examples:

```json
"allowRead": ["~/code/my-app", "~/code/shared-package"]
```

```json
"network": {
  "allowedDomains": ["api.cloudflare.com", "*.supabase.co"]
}
```

For shared config, import named fragments and keep project-specific hosts in the
profile:

```json
{
  "imports": ["node-app-defaults", "cloudflare-wrangler"],
  "network": {
    "allowedDomains": [
      "akcvwaclnbxroirpbesp.supabase.co",
      "*.supabase.co",
      "api.iconify.design"
    ]
  }
}
```

Named imports resolve from `templates/imports/<name>.json`. Relative imports
resolve next to `.guard/guard.json`. Imported arrays are merged without
duplicates, while local object and scalar values override imported defaults.

Use `homeLinks` only for narrow tool-owned config paths. The link is created
inside Guard's fake `HOME` before the sandbox starts, but the real source path
still needs an explicit filesystem allow rule.

For exploratory runs, prompt on first access to an unknown proxied host:

```sh
guard --ask-network pnpm run dev
guard --ask-network bash
```

Or enable it in the profile:

```json
"network": {
  "ask": true,
  "allowedDomains": [],
  "deniedDomains": []
}
```

Interactive shells use a macOS dialog for network prompts to avoid terminal job
control conflicts. Use `GUARD_ASK_NETWORK_UI=tty` to force terminal prompts or
`GUARD_ASK_NETWORK_UI=dialog` to force dialog prompts.

Prefer `${GUARD_PROJECT_DIR}` over a hardcoded local path so private repo
configs still work after a fresh checkout in a different location. Do not relax
`denyRead` unless the project has a clear reason to inspect the whole home
directory or all mounted volumes.
