# guard

`guard` runs developer tools and selected native macOS UI apps inside a local
macOS sandbox. It is an early alpha for local developer workflows, not a
production security product or a system-wide firewall.

The goal is simple: when you open an unfamiliar repo, install dependencies, run
a dev server, or launch a high-risk app profile, the process should not get
implicit access to your whole home directory, mounted volumes, secrets, or
arbitrary network destinations. `guard` makes that access explicit and
reviewable through project and app profiles, with policy checks for filesystem
access, subprocess launches, and network egress.

It supports two main workflows:

- **Developer commands**: run `node`, `pnpm`, `npm`, `python`, `pip`, and other
  project tools under a fail-closed filesystem and network policy.
- **Native UI apps**: launch built-in app profiles for Zoom, Microsoft Teams,
  and Webex, or install optional `Guard <App>.app` wrappers that show the
  effective permissions before opening the app.

Under the hood, `guard` generates local `sandbox-exec` profiles, provides
PATH-based shims for risky toolchains, creates per-run fake home/temp
directories, and routes cooperative network clients through Guard's proxy path.
For guarded runs, the default network backend is the deep `iron-proxy` path so
HTTP/TLS requests can be reviewed by host, method, path, and selected headers.
Guard is macOS-focused and does not depend on a remote service.

That gives Guard three practical review surfaces today:

- **Filesystem**: deny broad home, volume, application, and secret paths unless
  the profile reopens them.
- **Subprocesses**: optionally deny child process launches by default and block
  common download/script helper tools from install scripts. Package install
  commands can also run under a narrower PMG-style installation sandbox.
- **Network**: constrain direct raw egress, route cooperative clients through
  HTTP/SOCKS proxy variables, and use `iron-proxy` for deeper HTTP/TLS policy.

Guard is not currently a system-wide Little Snitch replacement. Apps that are
not launched through Guard are outside Guard's enforcement boundary unless they
voluntarily use Guard's proxy settings. The native monitor, daemon, and Network
Extension materials are prototype/planning surfaces for local testing; they are
not signed, notarized, installer-ready, or suitable for production enforcement.

## Quick Start

Install the latest CLI release. This is the normal path for macOS users and it
bundles `iron-proxy`.

```sh
curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh | sh
```

If `~/.local/bin` is not already on your `PATH`, add the line printed by the
installer to your shell profile, then open a new terminal.

Check the install:

```sh
guard doctor
```

Start in the repo you want to run:

```sh
cd ~/code/my-project
guard init
guard doctor
```

Run commands by putting `guard` first:

```sh
guard pnpm install
guard pnpm run dev
guard --ask-network pnpm run dev
guard npx vite --host 127.0.0.1
guard bash
```

`guard --ask-network` uses the bundled `iron-proxy` backend for HTTP/S decisions
so prompts can be scoped to a host, method, and path. When Guard prompts for a
new destination, approve the narrowest useful scope. To add reviewed rules
explicitly:

```sh
guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
guard profile add network.allowedDomains registry.npmjs.org
```

Launch a guarded native app profile:

```sh
guard run zoom
guard run teams
guard run webex
guard install-apps
```

`guard`, `guard --ask-network`, and `guard --deep-egress --ask-network` are
daemon-free per-run flows. They do not require `guardd`, Guard.app, a launch
agent, or a Network Extension.

## What It Protects

Default project profiles are intentionally narrow:

- deny reads from user homes, mounted volumes, `/Applications`, `/cores`, and
  `/home`
- reopen only the current project and guard's per-run directory
- allow writes only to the project and per-run directory
- block common secret writes such as `.env`, `*.pem`, `*.key`, and `secrets/`
- allow localhost dev-server binding without granting broad outbound network
  access

App profiles use the same idea for native UI apps: deny broad local filesystem
access, reopen only the app bundle and required app data paths, and constrain
network egress to the vendor domains that profile needs.

### Running Guard inside another sandbox

Guard can run under a parent sandbox such as Codex, but the parent must allow
Guard's own localhost control plane to start. When a profile uses network ask,
domain allowlists, HTTP rules, or the `iron-proxy` backend, Guard binds
ephemeral `127.0.0.1` listeners for its proxy and policy decision service before
it launches the protected child process.

The parent sandbox should allow Guard itself to bind and accept localhost high
ports, plus read/write Guard's per-run directory. Guard still generates the
child sandbox and enforces the child's filesystem, process, and network policy.
If the parent blocks these listeners, Guard fails before the child command
starts with a loopback control-plane bind error.

`guard` is not a VM and is not a replacement for a separate macOS user account
or full virtualization. It is a practical local containment layer for everyday
developer workflows and selected UI apps where running unsandboxed would be too
permissive.

## Install

### macOS CLI Install

Requirements:

- macOS on Apple Silicon
- Node.js 20 or newer, for example `brew install node`
- `~/.local/bin` on `PATH`

```sh
curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh | sh
```

The script downloads this release asset:

```text
guard-cli-0.1.0-darwin-arm64.tar.gz
```

It installs into `~/.local/guard`, links `guard` and bundled `iron-proxy` into
`~/.local/bin`, and runs onboarding setup. Users do not need to download
`iron-proxy-darwin-arm64` separately.

Install a specific release:

```sh
GUARD_VERSION=v0.1.0 \
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh)"
```

Use a different install prefix:

```sh
GUARD_PREFIX=/opt/guard \
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh)"
```

If Guard is already installed, the installer exits without replacing it. To
replace an existing release install or overwrite release links:

```sh
GUARD_FORCE=1 \
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh)"
```

If the installer finds a developer checkout or Guard shim already on `PATH`, it
keeps it in place and tells you what it found. Use `GUARD_FORCE=1` only when you
want the release install to take over the `guard` link.

For a private repo or private release, clone the repo first and run the local
script with a token that can read releases:

```sh
GH_TOKEN=... sh ./install.sh
```

### Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/uninstall.sh | sh
```

This removes `~/.local/guard` plus the `guard` and `iron-proxy` links from
`~/.local/bin`. It keeps `~/.config/guard` so project policy and local settings
are not deleted accidentally.

Remove config and local policy state too:

```sh
GUARD_REMOVE_CONFIG=1 \
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/uninstall.sh)"
```

### Manual Install

If you already downloaded `guard-cli-0.1.0-darwin-arm64.tar.gz`:

```sh
mkdir -p ~/.local/guard ~/.local/bin
tar -xzf guard-cli-0.1.0-darwin-arm64.tar.gz -C ~/.local/guard --strip-components=1
ln -sfn ~/.local/guard/bin/guard ~/.local/bin/guard
ln -sfn ~/.local/guard/bin/iron-proxy ~/.local/bin/iron-proxy
~/.local/guard/bin/guard setup --yes --bin-dir ~/.local/bin --code-root ~/code --force --no-shims
```

### Developer Installs

Package-manager and source installs are for contributors. They do not bundle
`iron-proxy`.

`guard setup` can be run before or after a source install. It shows the current
managed root, config file, install directory, PATH status, and installed
entrypoint/shim links, then asks for the managed code root, install directory,
and whether to install PATH shims. For non-interactive shells, pass explicit
flags:

```sh
guard setup --yes --code-root ~/code --bin-dir ~/.local/bin
```

The managed code root is the top-level folder where you keep projects that
Guard should manage through its shims. `~/code` is a common choice, but it is
not special: use `~/src`, `~/dev`, `~/Projects`, or any other parent directory
that matches your local workflow. Interactive setup suggests a folder under
your home directory when the saved config points somewhere temporary or outside
your home. The install links directory is where Guard creates command symlinks
such as `guard`, `guard-zoom`, and optional tool shims; for a user-local install
this is usually `~/.local/bin`.

Guard also ships agent-facing project guidance. In a repo where you want a
coding agent to help maintain Guard policy, run:

```sh
guard init-agent
```

This creates `AGENTS.md` from `templates/agents/AGENTS.md` with instructions for
generating and reviewing `.guard/guard.json` safely.

To install the standard shim set into `~/.local/bin`:

```sh
guard install --code-root ~/code
```

To install only `guard` and the app launchers:

```sh
guard install --code-root ~/code --no-shims
```

## Build Artifacts

`npm run build:package` is the recommended release build for GitHub alpha
testers because it bundles the matching OS binary for the `iron-proxy` backend.
By default it clones
`https://github.com/oripka/iron-proxy` at `main`, builds
`./cmd/iron-proxy`, keeps the resulting binary as a private build intermediate,
and writes it into each installable edition as `bin/iron-proxy`.

The same command also emits edition tarballs:

- `guard-cli-<version>-<platform>-<arch>.tar.gz`: CLI, shared policy code,
  profiles/templates, docs, and `iron-proxy`; no `guardd` or native UI.
- `guard-daemon-<version>-<platform>-<arch>.tar.gz`: CLI plus `guardd` and
  `iron-proxy`; no native UI.
- `guard-desktop-<version>-darwin-<arch>.tar.gz`: macOS desktop edition with
  CLI, `guardd`, native sources, the built `GuardMacApp` binary, and
  `iron-proxy`.

Each edition includes `install.sh` and `uninstall.sh`. After unpacking, run:

```sh
./install.sh
```

The installer links `guard` and bundled `iron-proxy` into `~/.local/bin` by
default, then runs Guard's normal onboarding setup so users do not need to set
`GUARD_IRON_PROXY_BIN`. Pass a prefix to install links elsewhere:

```sh
./install.sh /opt/guard
```

Tagged pushes such as `v0.1.0` publish a GitHub Release with both
macOS and Linux edition tarballs plus SHA256 checksum files. Users should only
need the matching `guard-cli-<version>-<platform>-<arch>.tar.gz` asset for a
CLI install; it already includes `iron-proxy`. The release notes label the CLI
as alpha and the daemon/desktop editions as experimental.

Override the source when needed:

```sh
GUARD_IRON_PROXY_REPO=https://github.com/oripka/iron-proxy \
GUARD_IRON_PROXY_REF=main \
npm run build:package
```

To install into a different directory:

```sh
guard install --bin-dir ~/bin --code-root ~/work --force
```

`guard install` creates symlinks back to the real `guard` entrypoint. Packaged
editions also include a bundled `bin/iron-proxy`, and Guard automatically
discovers that binary when running from an unpacked edition. It also writes the
managed root to `~/.config/guard/config.json`. The managed root should usually
be the parent directory that contains your source checkouts, for example
`~/code`, `~/src`, `~/dev`, or `~/Projects`; set `GUARD_CODE_ROOT` to override
that value for a single shell or CI job.

### Linux Status

Linux support is experimental and intentionally limited. The current
`bubblewrap` backend can fail closed for basic filesystem containment and
network-denied runs. It also supports local development processes with an
isolated loopback interface when `allowLocalBinding` or `allowLoopbackPorts`
are configured, which lets a guarded web app talk to its own localhost service
while external egress stays blocked. Guard proxy/domain/httpRules, TLS
inspection through `iron-proxy`, and `allowedRawTcp` are not supported there
yet. Treat Linux as a compatibility target, not a polished release platform for
the alpha.

### Signing and Notarization

The alpha CLI and tarball editions are not notarized. That matches the current
distribution goal: easy test artifacts, not a polished signed macOS product
installer. The desktop bundle remains experimental until a later signing,
notarization, and installer pass.

## Usage

### Everyday Developer Commands

The clearest mode is explicit Guard:

```sh
guard pnpm install
guard pnpm run dev
guard node scripts/build.mjs
guard pip install -r requirements.txt
guard npx vite --host 127.0.0.1
guard --ask-network pnpm run dev
```

Common runs get these policies:

| Command | Policy applied |
| --- | --- |
| `guard pnpm install` | Project profile plus the package-install sandbox when enabled. Writes are narrowed to install artifacts such as `node_modules`, lockfiles, caches, and local virtualenvs; secrets and Git hooks stay denied. Package threat intelligence, dependency cooldown, and package lookup apply when configured. |
| `guard pnpm run dev` | Normal project profile. The project and Guard run directory are reopened, localhost dev-server binding is allowed, and network egress follows `network.allowedDomains`, `network.httpRules`, ask prompts, and proxy settings. |
| `guard node scripts/build.mjs` | Normal project profile for a direct script. Filesystem, subprocess, and network rules come from `.guard/guard.json`; the install sandbox does not turn on unless forced. |
| `guard pip install -r requirements.txt` | Python package-install run. With install sandbox enabled, Guard allows package/cache/virtualenv writes and keeps user secrets denied. |
| `guard npx ...` | Explicit one-off package-tool run. `npx` shims are disabled by default, so use this form when you want Guard policy around `npx`. |
| `guard --ask-network ...` | Same filesystem and subprocess policy, plus prompts for unknown proxied HTTP/S requests. Exact `network.httpRules` allow silently. |

If you install shims with `guard setup`, common tool commands are guarded inside
the managed code root:

```sh
guard setup
pnpm install
pnpm run dev
node scripts/build.mjs
```

The enabled shims are `node`, `pnpm`, `npm`, `python`, `python3`, `pip`, `pip3`,
and `uv`. `npx`, `corepack`, and `deno` are disabled by default because they are
easy to misuse as hidden download or execution paths. Outside the managed root,
the shims run the real tools normally; inside the managed root, unconfigured
directories fail closed in non-interactive shells.

Use profile commands for the common edits:

```sh
guard init
guard doctor
guard profile add network.allowedDomains registry.npmjs.org
guard profile add filesystem.denyRead ~/.ssh
guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
```

For subprocess hardening, use `--deny-subprocesses`,
`process.denyByDefault`, and `process.allowedExecutables`; see
[Child Process Policy](#child-process-policy).

### Guard Native UI Apps

Built-in UI app profiles can be launched from any directory:

```sh
guard run zoom
guard run teams
guard run webex
```

You can also run the vendor binary explicitly with a built-in profile:

```sh
guard --profile zoom -- /Applications/zoom.us.app/Contents/MacOS/zoom.us
guard --profile teams -- "/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams"
guard --profile webex -- /Applications/Webex.app/Contents/MacOS/Webex
```

After installing app launchers, you can also start the guarded UI apps through
PATH commands:

```sh
guard-zoom
guard-teams
guard-webex
```

Or install native macOS wrappers in `~/Applications`:

```sh
guard install-app webex
guard install-app teams
guard install-app zoom
guard install-apps
```

Those wrappers appear as `Guard Zoom.app`, `Guard Teams.app`, and
`Guard Webex.app`. Each wrapper shows a native preflight summary of the profile,
including filesystem, network, and warning status, before launching the real
app through `guard`.

## Integration Model

`guard` is the only real entrypoint. Everything else is one of two modes:

- explicit runs: `guard -- <command> ...`
- shimmed runs: `pnpm ...`, `node ...`, `python3 ...`

Shim mode is intentionally narrow:

- if a `.guard/guard.json` exists in the current repo tree, the shim re-enters
  `guard` and runs under policy
- if the current directory is inside the managed root and no config exists, the
  shim prompts in an interactive shell and fails closed in non-interactive use
- if the current directory is outside the managed root, the shim runs the real
  tool unchanged

This keeps Codex and local shell behavior aligned without relying on shell
aliases or tool-specific wrapper scripts.

## Command Reference

Run `guard help` for the full CLI reference. Most daily use fits this shape:

```text
guard [options] <command> [args...]
guard --ask-network <command> [args...]
guard --install-sandbox <package-install-command> [args...]
guard off <command> [args...]
```

Common commands:

```sh
guard init
guard doctor
guard audit
guard profile doctor
guard profile add network.allowedDomains registry.npmjs.org
guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
guard profile add-raw-tcp --host localhost --resolve-at-launch --port 8976 --reason "local callback"
guard run zoom
guard ui
```

Common one-run flags:

- `--ask-network`: prompt for unknown proxied HTTP/S destinations.
- `--install-sandbox`: force the package-install sandbox for one run.
- `--install-sandbox-allow type=value`: add a one-run exception. Supported
  types are `read`, `write`, `exec`, `domain`, `net`, and `net-bind`.
- `--deny-subprocesses`: deny child process execution unless explicitly
  allowed.
- `--allow-read PATH`, `--allow-write PATH`, `--deny-read PATH`, and
  `--deny-write PATH`: add one-run filesystem rules.
- `--allow-domain HOST` and `--deny-domain HOST`: add one-run network domain
  rules.
- `--allow-loopback-port PORT`: add one exact localhost TCP exception.
- `--no-network` and `--network-unrestricted`: force no egress or unrestricted
  egress for one run.

Package installs can opt into PMG-style controls in `.guard/guard.json`:

```json
{
  "supplyChain": {
    "installSandbox": true,
    "dependencyCooldown": { "enabled": true, "days": 5 },
    "threatIntelligence": {
      "blockedPackages": ["pkg:npm/safedep-test-pkg@1.0.0"]
    }
  },
  "network": {
    "allowedDomains": ["registry.npmjs.org"],
    "packageLookup": { "provider": "socket-free" }
  }
}
```

`installSandbox` narrows package-manager writes during `pnpm install`,
`npm install`, `pip install`, and similar install/download commands.
`threatIntelligence` blocks known-bad package PURLs before artifact download
using local rules, Socket lookup alerts when configured, or an adapter endpoint.
`dependencyCooldown` filters npm and PyPI metadata so freshly published versions
inside the cooldown window are not selected. See
[docs/supply-chain-policy.md](docs/supply-chain-policy.md) for the full schema,
event names, adapter contract, and limitations.

## Native App Launchers

Install the local monitor app:

```sh
guard ui
```

This builds and starts the prototype `Guard Monitor.app` as a lightweight
menu-bar utility for local testing. It shows only the toolbar/status icon by
default. On launch, the monitor
connects to an existing local `guardd` if one is reachable; otherwise it starts
a temporary local daemon using the selected project when available or Guard's
global app-support policy store by default. Use the menu-bar icon to open the
full monitor, rules, or settings windows when needed.

Install the local monitor app without opening it:

```sh
guard install-monitor
```

`Guard Monitor.app` reads the persistent event log at
`~/Library/Application Support/guard/events.jsonl` by default. Guard writes
process lifecycle, sandbox profile, proxy startup, network decision, and
best-effort macOS sandbox denial events there as JSON lines. Override the
location with `GUARD_STATE_DIR` or
`GUARD_EVENT_LOG` before launching guarded commands or installing the monitor.

On macOS, each guarded run tags its generated sandbox profile with a unique
`with message` value and starts one filtered `log stream` process for that run.
This avoids polling the unified log and lets Guard surface actionable
`sandbox.denial` monitor events when macOS emits them. By default Guard records
subprocess blocks, meaningful direct network blocks, and sensitive file events
such as canary files, SSH private keys, cloud credentials, and key material;
ordinary low-signal sandbox chatter stays out of the event log. Set
`GUARD_SANDBOX_DENIAL_LOGS=all` for verbose diagnostics, or
`GUARD_SANDBOX_DENIAL_LOG=0` to disable this best-effort bridge. It is useful
local telemetry for simple per-run mode, not a replacement for a future Endpoint
Security or Network Extension backend.

Default high-severity file alerts are intentionally low false-positive:
`.guard-canary*` / `guard-canary*` / `canary/...` paths, SSH private keys,
cloud and cluster credentials (`~/.aws/credentials`, `~/.config/gcloud`,
`~/.azure`, `~/.kube/config`), developer token files (`~/.config/gh/hosts.yml`,
`~/.npmrc`, `~/.pypirc`, `~/.netrc`), Terraform/Cargo/Gem credentials, GnuPG
private keys, KeePass databases (`*.kdbx`, `*.kdb`), and private key material
such as `*.pem`, `*.key`, `*.p12`, and `*.pfx`. Guard Monitor shows this
default watchlist under Filesystem Policy.

The same data is available without opening the app:

```sh
guard monitor-log
guard monitor-log --json --limit 100
```

The daemon prototype exposes recent events over localhost:

```sh
guard daemon --port 8765
curl http://127.0.0.1:8765/health
curl 'http://127.0.0.1:8765/events?limit=20&type=network.decision'
```

When `Guard Monitor.app` can reach `guardd`, its right-side inspector uses the
daemon as the write path. The Rules button opens the selected profile's allow,
deny, HTTP, disabled-rule, and version summary. The Templates button opens a
focused template window that can preview or apply bundled templates through
`guardd`. The Settings button opens daemon, TLS, extension, and diagnostics
controls; it can start a local temporary `guardd` using the selected event
project when available, otherwise Guard's global app-support policy root under
`~/Library/Application Support/guard`; it can also stop that monitor-managed
daemon, toggle explicit TLS policy for the selected profile, and edit visible
rules with enable/disable/delete row actions. The Log button opens recent JSONL
history in a separate diagnostics window instead of occupying the main monitor.
`guardd` can also write the canonical shared-policy snapshot used by the
NetworkExtension app-group sync manifest/policy/event paths through
`POST /extension/sync`; the unsigned scaffold consumes that contract for policy
cache invalidation, policy digest validation, stale-policy fallback, and
event-log backpressure. These controls are feature-only local development
flows; they do not install launch agents or NetworkExtension components.

The monitor UI is prototype-grade and intended for local development feedback.
It points toward a native macOS security workflow, but it is not a signed,
notarized, production installer and should not be described as a finished
Little Snitch-style product. Today it provides profile risk and rule status
chips, a compact live allow/deny traffic graph, and a Focus Top Host action
that opens the Rules window filtered to the busiest recent destination. Rules
carry action, type, enabled state, and scope-risk labels so broad host/domain
grants are easier to spot before editing. The dedicated Rules window supports
multi-select edits, a Disable Visible bulk action, and optimistic
profile-version checks so stale UI edits reload instead of silently overwriting
newer CLI or daemon changes.

Review TLS inspection explicitly:

```sh
guard settings
guard tls status
guard profile tls enable --json
guard profile tls disable --json
```

TLS inspection uses the `iron-proxy` backend with a per-run CA scoped to the
guarded process environment. Guard does not install a global trusted CA as part
of these commands. `guardd` can generate, rotate, and revoke local CA artifacts
and can issue cached per-host leaf certificates under its state directory for
development, but it always reports `globalTrustManaged: false`. `guardd` also
exposes `/tls/status` for trust diagnostics and `/security/status` for local
token, permission, and CA-key checks. `/events/query` scans the persisted JSONL
log tail for filtered history when the in-memory monitor buffer is not enough,
while `/events/index` keeps durable counts for long-running history summaries.
`/alerts/decision` records allow/deny decisions for `once`, `session`, or
`forever`; forever decisions persist profile rules with optimistic version
checks. `/alerts/pending` and `/alerts/:id/resolve` provide the live alert
lifecycle used by native monitor controls: pending alerts carry `createdAt`,
`expiresAt`, and `timeoutMs`, resolution emits normal decision history plus a
resolved event, and expired alerts are marked explicitly instead of lingering as
ambiguous unanswered prompts. Pending alert state is persisted under the daemon
state directory so unresolved prompts survive a `guardd` restart.

For local secret hardening, `GUARDD_TOKEN_KEYCHAIN=1` lets `guardd` read its API
token from macOS Keychain when no token is supplied on the command line, and
`POST /auth/token/persist` can store the current runtime token through the
system `security` tool. This is still separate from packaging/signing.

The native monitor Settings window includes the guided TLS trust onboarding flow.
It reads the existing `GET /tls/status` payload and shows the local CA lifecycle,
certificate and bundle paths, process-scoped trust environment variables,
cached host-certificate counts, expired-certificate diagnostics, and any CA
permission or lifecycle findings. The trust actions are deliberately local:
Generate Local CA creates daemon-state artifacts, Rotate Local CA archives and
replaces those artifacts for recovery, and Revoke Local CA marks the local CA
metadata revoked. None of these actions install or modify global macOS trust;
guarded tools must receive the per-process trust environment from Guard.

`guard install-app webex`, `guard install-app teams`, and `guard install-app zoom`
are optional. They create native macOS wrapper apps in `~/Applications` by
default. Each wrapper uses AppKit, copies the vendor app icon, shows the
effective Guard permissions before launch, and only starts the app when you click
Launch.

Install all bundled native app wrappers at once:

```sh
guard install-apps
```

Native app wrappers require Xcode Command Line Tools because they compile and
ad-hoc sign a small Swift launcher locally.

The generated apps are intentionally thin:

- `Contents/MacOS/GuardAppLauncher`: compiled from
  [native/macos-launcher/GuardAppLauncher.swift](native/macos-launcher/GuardAppLauncher.swift)
- `Contents/Resources/GuardAppConfig.json`: profile name and absolute `guard`
  path
- `Contents/Resources/GuardAppIcon.icns`: copied from the vendor app when
  present

Reinstall with `--force` after changing the Swift launcher or moving this repo:

```sh
guard install-app webex --force
guard install-app teams --force
guard install-app zoom --force
guard install-app all --force
```

## Real Tool Resolution

The fragile part is not the symlink to `guard`; it is finding the actual
underlying `node`, `pnpm`, `python3`, and similar tools after Homebrew or
package-manager updates.

The launcher therefore resolves real tools in this order:

1. explicit override env var such as `GUARD_REAL_NODE`
2. sanitized `PATH`, with guard shim directories removed
3. a small fallback list for common macOS installs

That makes the shims resilient across Homebrew and package-manager updates while
still avoiding recursion through `~/.local/bin`.

Relevant environment variables:

- `GUARD_CODE_ROOT`
- `GUARD_CONFIG_DIR`
- `GUARD_SHIM_DIR`
- `GUARD_SHIM_DIRS`
- `GUARD_REAL_NODE`
- `GUARD_REAL_PNPM`
- `GUARD_REAL_NPM`
- `GUARD_REAL_PYTHON`
- `GUARD_REAL_PYTHON3`
- `GUARD_REAL_PIP`
- `GUARD_REAL_PIP3`
- `GUARD_SOCKS_PROXY` (injected into guarded processes when a SOCKS backend is active)
- `GUARD_SSH_PROXY_COMMAND` (injected into guarded processes for SSH helpers)

## Doctor

`guard doctor` shows the current integration state:

- current working directory
- managed root
- user config from `~/.config/guard/config.json`
- whether the current directory is inside the managed root
- project and built-in profile matches
- effective profile source
- shim directories
- sanitized `PATH`
- runtime Node resolution
- resolved tool paths for the guarded shims

This is the first command to run when a shim behaves differently than expected.

## Project Bootstrap

For a new Node-style project:

```sh
cd ~/code/my-project
guard init
guard doctor
guard pnpm run dev
```

That gives you:

- a local `.guard/guard.json`
- strict default read denies for `~/`, `/Volumes`, `/Applications`, `/cores`,
  and `/home`
- explicit project and per-run write carve-outs
- a reproducible config that can live in the repo

For a Cloudflare Wrangler or Nitro deploy project:

```sh
cd ~/code/course-planning
guard init cloudflare-wrangler --force
guard pnpm run build
guard npx wrangler --cwd .output deploy
```

The Cloudflare template imports the Node app defaults, adds Cloudflare API
domains, Workers/Pages preview domains, Wrangler dev ports `8787` and `8788`,
Wrangler's OAuth callback port `8976`, and a narrow home link for
`~/Library/Preferences/.wrangler/config` so an existing Wrangler OAuth login can
be reused and refreshed. If Wrangler prints a different
`redirect_uri=http://localhost:<port>/oauth/callback`, add that port to
`network.allowLoopbackPorts`.

For CI or repeatable non-interactive deploys, prefer `CLOUDFLARE_API_TOKEN`.

## What To Guard

Guard tools that either execute project-controlled code or install/fetch code:

- keep auto-shims for `node`, `pnpm`, `npm`, `python`, `python3`, `pip`, `pip3`,
  and `uv`; add `deno` only when the native runtime supports it
- keep `npx` and `corepack` disabled by default because they are easy
  one-command remote execution paths
- use explicit `guard <tool> ...` for `make`, `just`, `go`, `cargo`, `poetry`,
  `bun`, `yarn`, `gem`, `bundle`, `mvn`, and `gradle` when working in
  an untrusted or freshly updated project
- keep `docker` and `/var/run/docker.sock` outside the default policy; granting
  Docker socket access is effectively host access
- do not globally shim `sh`, `zsh`, `bash`, or `git` for now; the usability cost
  is high and it can break normal system workflows. Use `guard git ...` or
  `guard make ...` explicitly when a repository itself is untrusted.

The shims protect normal PATH-based invocations. Absolute paths such as
`/opt/homebrew/bin/node` intentionally bypass the shim and should be treated as
an explicit escape hatch.

## Interactive Network Ask

Guard enables per-run ask-and-learn prompts by default for proxied HTTP/S
requests under the `iron-proxy` backend. `guard --ask-network <command>` remains
as an explicit compatibility flag.

Approving an exact or path rule saves a `network.httpRules` entry in the current
project profile when learning is enabled, so matching requests allow silently in
later runs. Approving a domain allows that host for the rest of the current run.
Denying blocks the request for the current run. If an existing
`network.allowedDomains` entry matches, interactive runs offer to upgrade it to
a narrower path rule; non-interactive runs keep allowing the domain and record
the suggested path rule in the event log instead of breaking existing workflows.
Non-interactive unknown requests still fail closed instead of waiting for input.

When the guarded command is an interactive shell such as `bash` or `zsh`, guard
uses a macOS dialog for the prompt so the parent proxy process does not fight the
child shell for terminal control. Set `GUARD_ASK_NETWORK_UI=tty` to force the
terminal prompt, `GUARD_ASK_NETWORK_UI=dialog` to force AppleScript dialogs, or
`GUARD_ASK_NETWORK_UI=native` to use the bundled Swift helper panels.

The same mode can be enabled in a profile:

```json
"network": {
  "ask": true,
  "learnHttpRules": true,
  "upgradeDomainAllows": true,
  "allowedDomains": [],
  "deniedDomains": []
}
```

This applies to traffic that goes through guard's HTTP/SOCKS proxy support.
Direct raw TCP remains controlled by the native sandbox profile.

### Advanced Network Policy

The default Guard proxy backend and the `iron-proxy` backend expose the same
client-facing proxy contract. Guard sets common HTTP proxy variables,
`GUARD_SOCKS_PROXY`, and `GUARD_SSH_PROXY_COMMAND`, so helper scripts can route
SSH through the per-run SOCKS listener without learning backend-specific
internals.

`iron-proxy` profile rules can combine compatibility domain allows, narrower
method/path rules, and boundary-side secret injection:

```json
{
  "network": {
    "backend": "iron-proxy",
    "ask": true,
    "learnHttpRules": true,
    "upgradeDomainAllows": true,
    "allowedDomains": ["registry.npmjs.org"],
    "httpRules": [
      {
        "host": "api.openai.com",
        "methods": ["POST"],
        "paths": ["/v1/responses", "/v1/oripka/*"]
      }
    ],
    "secretInjection": [
      {
        "name": "OPENAI_API_KEY",
        "source": { "type": "env", "var": "OPENAI_API_KEY" },
        "proxyValue": "guard-proxy-openai-token",
        "matchHeaders": ["Authorization"],
        "require": true,
        "rules": [
          {
            "host": "api.openai.com",
            "methods": ["POST"],
            "paths": ["/v1/responses"]
          }
        ]
      }
    ]
  }
}
```

Secret injection is boundary-side only. The guarded process sends the proxy
token, for example `Authorization: Bearer guard-proxy-openai-token`; Guard
renders an `iron-proxy` `secrets` transform that swaps it for the real
environment secret only on matching host/method/path rules. Profile JSON stores
secret names and proxy tokens, not real secret values, and monitor UI surfaces
secret routes as redacted rows.

`guard --daemon-policy <command>` is the daemon-backed variant. It forces
ask-style proxy decisions, writes `network.decisionMode: "guardd"` into the
temporary runtime config, and posts unknown destinations to `POST
/alerts/pending`. The guarded process waits until the alert is resolved through
`POST /alerts/:id/resolve` or `POST /alerts/decision`; unresolved or unreachable
daemon decisions are denied. This works with both the normal Guard proxy and
`guard --deep-egress` / `network.backend: "iron-proxy"`.

Use `network.allowedRawTcp` only for narrow loopback tools that cannot use proxy
environment variables. Host rules must opt into launch-time DNS resolution, and
Guard renders supported loopback results as exact sandbox egress rules for the
current run:

```json
{
  "network": {
    "allowedRawTcp": [
      {
        "host": "localhost",
        "resolveAtLaunch": true,
        "port": 8976,
        "reason": "local OAuth callback helper"
      }
    ]
  }
}
```

Prefer the proxy path when possible. `allowedRawTcp` is intentionally separate
from `allowedDomains`: domain rules constrain traffic through Guard's proxy
policy, while raw TCP rules are exact sandbox exceptions for non-proxyable
clients and should stay host/IP plus port scoped. Current macOS
`sandbox-exec` profiles do not support exact external `IP:port` egress rules;
for SSH to hosts such as `ec2.packetsafari.com`, use the injected
`GUARD_SSH_PROXY_COMMAND` or `GIT_SSH_COMMAND` so the traffic goes through
Guard's SOCKS proxy. A future Network Extension backend is the right place for
exact external raw TCP rules.

`network.allowLocalBinding` is intentionally loopback-only. It permits local dev
servers to listen on localhost without allowing direct outbound TCP, DNS, or
ICMP egress. For dev tools that need to call back into localhost helper
services, prefer exact `network.allowLoopbackPorts`.

Note: `network.allowLoopbackPorts` authorizes a localhost port number, not a
specific process. Only list ports that are stable and expected for the project;
if a different local service later binds the same port, the sandbox cannot
distinguish it from the intended helper.

Guard intentionally does not provide a blanket "high loopback ports" option.
macOS sandbox profiles do not support compact port ranges, and allowing all high
localhost ports is broad enough to be misleading. Prefer exact
`network.allowLoopbackPorts`, or use `network.allowLoopbackListeningHighPorts`
when the helper service is already listening before the guarded command starts.

`network.allowLoopbackConnections` permits all localhost TCP ports and should be
treated as an escape hatch.

`guard` no longer depends on the external `srt` package. The supported alpha
runtime uses macOS `sandbox-exec` while keeping policy generation local to this
repo. A Linux `bubblewrap` backend exists as an experimental compatibility
target for later work.

The Linux backend is intentionally narrower than the macOS backend today:

- filesystem containment is built from read-only and writable bind mounts
- network-denied runs use a private `bubblewrap` network namespace
- loopback-only local development runs use a private `bubblewrap` network
  namespace with `lo` enabled before the guarded command starts
- `networkUnrestricted: true` uses the host network for trusted commands
- `network.linuxBackend: "host-proxy"` enables Guard proxy/domain allowlists, HTTP rules, `iron-proxy` TLS inspection, and `allowedRawTcp` for proxy-aware clients while keeping filesystem containment
- `network.linuxBackend: "policy-helper"` creates a Linux network namespace, connects it through a veth pair to Guard's proxy, installs nftables allow rules for the proxy and `allowedRawTcp`, and records nftables denial counters as `sandbox.denial` events
- `policy-helper` requires root plus `ip` and `nft`; use `host-proxy` when those privileges are unavailable and direct-socket kernel blocking is not required

The native runtime now lives in:

- `lib/guard-manager.mjs`
- `lib/guard-utils.mjs`
- `lib/guard-bubblewrap.mjs`

It also supports a few local-only policy extensions that are useful for native
macOS apps:

- `networkUnrestricted: true`
- `system.allowFileIssueExtension`
- `system.allowMachIssueExtension`
- `system.allowSysctlRead`
- `system.allowIokitRegistryEntryClass`
- `system.allowIokitUserClientClass`
- `system.allowFileIoctl`

Current native-runtime limitation: `deno` is fail-closed in the shim because it
crashes under macOS `sandbox-exec` even with a minimal profile.

## Reference Policy

Use [docs/node-app-policy.md](docs/node-app-policy.md) for Node/Nuxt/Vite/Slidev
projects.

Use [docs/supply-chain-policy.md](docs/supply-chain-policy.md) for package
threat intelligence, dependency cooldown, install sandboxing, and install
hardening.

Use [docs/project-profiles.md](docs/project-profiles.md) for the current local
PacketSafari, Wireshark, and on-prem profile conventions.

Use [docs/critical-app-profiles.md](docs/critical-app-profiles.md) for the
Teams, Webex, and Zoom app-profile workflow.

Use [docs/zoom-policy.md](docs/zoom-policy.md) for Zoom-specific notes.

The reference policy denies reads from `/Users`, `/Volumes`, `/Applications`,
`/cores`, and `/home` by default. Every project must explicitly
reopen only the paths it needs in `allowRead`.

Template:

```text
templates/node-app/guard.json
templates/cloudflare-wrangler/guard.json
templates/imports/*.json
```

Copy it to:

```text
.guard/guard.json
```
The template uses `${GUARD_PROJECT_DIR}`, so most projects do not need an
absolute local path.

Project profiles can import shared fragments before applying local overrides:

```json
{
  "imports": ["node-app-defaults", "cloudflare-wrangler"],
  "network": {
    "allowedDomains": ["akcvwaclnbxroirpbesp.supabase.co", "*.supabase.co"]
  }
}
```

Named imports resolve from `templates/imports/<name>.json`. Relative imports
such as `"./local-domains.json"` resolve next to the profile file. Imported
arrays are merged without duplicates; local profile values are appended and
object/scalar fields override imported defaults.

Profiles can also declare `homeLinks` for tools that insist on reading from
`HOME`. Each entry links a real source path into Guard's fake home before the
sandbox starts; the profile must still explicitly allow the real source path in
`filesystem.allowRead` or `filesystem.allowWrite`.

## Packaging

This repo is set up as a normal Node package with executable bins:

- `guard`
- `guard-zoom`
- `guard-teams`
- `guard-webex`

Useful package commands:

```sh
pnpm test
pnpm doctor
npm pack --dry-run
```

## Sample Test App

The sample app verifies the important filesystem rules:

- project reads work
- project writes work
- home reads are denied
- home writes are denied
- `/Volumes` reads are denied
- controlled temp writes work
- Nitro-style Unix sockets are restricted to the per-run guard temp directory
- interactive CLI terminal mode is allowed for tools such as Slidev
- `.env` writes are denied

Run:

```sh
cd ~/src/guard/samples/node-app
PNPM_GUARD_BYPASS=1 pnpm test
```

The test runner intentionally starts `guard` itself for each case, so do not run
the test runner under an outer `guard`.
