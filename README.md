# guard

`guard` runs developer tools and selected native macOS UI apps inside a local
macOS sandbox.

The goal is simple: when you open an unfamiliar repo, install dependencies, run
a dev server, or launch a high-risk app profile, the process should not get
implicit access to your whole home directory, mounted volumes, secrets, or
arbitrary network destinations. `guard` makes that access explicit and
reviewable through project and app profiles.

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

Guard is not currently a system-wide Little Snitch replacement. Apps that are
not launched through Guard are outside Guard's enforcement boundary unless they
voluntarily use Guard's proxy settings. Future Network Extension or Endpoint
Security support is entitlement-gated and tracked only as future planning.

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

`guard` is not a VM and is not a replacement for a separate macOS user account
or full virtualization. It is a practical local containment layer for everyday
developer workflows and selected UI apps where running unsandboxed would be too
permissive.

## Install

Requirements:

- macOS with the native `sandbox-exec` runtime
- Node.js 20 or newer
- `~/.local/bin` or another user-writable bin directory on `PATH`
- Xcode Command Line Tools only if you want optional native `.app` wrappers

Package-manager install from GitHub:

```sh
pnpm add -g github:oripka/guard
guard setup
```

Or clone and link directly from the repo:

```sh
git clone https://github.com/oripka/guard.git ~/src/guard
~/src/guard/bin/guard setup
```

`guard setup` can be run before or after `guard install`. It shows the current
managed root, config file, install directory, PATH status, and installed
entrypoint/shim links, then asks for the managed code root, install directory,
and whether to install PATH shims. For non-interactive shells, pass explicit
flags:

```sh
guard setup --yes --code-root ~/code --bin-dir ~/.local/bin
```

To install the standard shim set into `~/.local/bin`:

```sh
guard install --code-root ~/code
```

To install only `guard` and the app launchers:

```sh
guard install --code-root ~/code --no-shims
```

To install into a different directory:

```sh
guard install --bin-dir ~/bin --code-root ~/work --force
```

`guard install` creates symlinks back to the real `guard` entrypoint. It does
not copy wrapper scripts around your system. It also writes the managed root to
`~/.config/guard/config.json`; set `GUARD_CODE_ROOT` to override that value for
a single shell or CI job.

## Usage

### Guard Developer Commands

From a project that contains `.guard/guard.json`, prefix commands with `guard`:

```sh
guard pnpm run dev
guard --ask-network pnpm run dev
guard --daemon-policy pnpm run dev
```

Guard uses the deep `iron-proxy` backend by default for guarded runs. Guard
starts `iron-proxy` for the run, injects proxy and CA environment variables,
keeps the sandboxed process limited to the local proxy, and enables ask-and-learn
HTTP policy by default. Exact `network.httpRules` allow silently. Existing
`network.allowedDomains` still work as compatibility allows, but interactive
runs ask whether to save a narrower path rule. Once a path rule is saved, Guard
does not ask again for that request shape.

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

Both the default Guard proxy backend and the `iron-proxy` backend expose an
HTTP proxy and a SOCKS proxy to the guarded process. Guard sets common proxy
environment variables, plus `GUARD_SOCKS_PROXY` and
`GUARD_SSH_PROXY_COMMAND`, so helper scripts can route SSH through the per-run
SOCKS listener without learning backend-specific details.

Use `--daemon-policy` to keep the per-run sandbox/proxy launcher but delegate
unknown network decisions to `guardd` pending alerts instead of prompting in the
current terminal. This is opt-in and fail-closed: set `GUARD_DAEMON_URL` or
`GUARDD_URL`, plus `GUARD_DAEMON_TOKEN` or `GUARDD_API_TOKEN` when the daemon is
authenticated. Guard enqueues `guard.alert.pending`, waits for Guard.app or a
daemon client to resolve it, then allows or denies the current proxied request.
The default `guard` and `guard --ask-network` paths remain daemon-free.

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

Use `--deny-subprocesses`, `process.denyByDefault`, or
`process.allowedExecutables` to constrain which binaries the guarded run may
launch. When these are absent, Guard keeps the current permissive
`process-exec` behavior. With `denyByDefault`, Guard automatically allows
`/usr/bin/env` and the command you launched, then the sandbox default deny
blocks other child process launches unless they are listed:

```sh
guard --deny-subprocesses bash
```

Even when child processes are otherwise allowed, Guard blocks child executions
of commonly abused download/script tools such as `curl`, `wget`, `python`,
`ruby`, `perl`, `osascript`, and `nc` by default. The explicit command still
works, so `guard curl https://example.com` is allowed, but a shell or install
script spawning `curl` is blocked unless the profile or run uses
`--allow-risky-child-tools`.

```json
{
  "process": {
    "denyByDefault": true,
    "allowedExecutables": [
      "/opt/homebrew/bin/node",
      "${GUARD_PROJECT_DIR}/node_modules/.bin/*"
    ]
  }
}
```

Profiles still need to include interpreters and helper tools spawned by the
initial command, such as `/bin/sh`, `python3`, package-manager shims, or
project-local binaries. On denial, `sandbox-exec` usually reports the attempted
exec to the process as `Operation not permitted`; Guard's profile rules include
a sandbox message tag for system-log correlation, but the portable CLI signal is
the command failure line from the blocked process.

When `ask` is enabled, unknown requests trigger an interactive prompt that can
allow an exact API path or a generated wildcard path for the current run.
Set `GUARD_ASK_NETWORK_UI=dialog` to use native macOS dialogs for ask decisions
even when a guarded app was launched from a native wrapper.
Set `GUARD_ASK_NETWORK_UI=native` to opt into the Swift helper panels; the
launcher builds and wires `GUARD_ASK_NETWORK_HELPER` automatically when needed.

You can persist reviewed rules back into the current project profile:

```sh
guard profile add network.allowedDomains registry.npmjs.org
guard profile add filesystem.denyRead ~/.ssh
guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
guard profile add-raw-tcp --host localhost --resolve-at-launch --port 8976 --reason "local OAuth callback"
```

Bootstrap a default project profile for a Node, Vite, Nuxt, Slidev, Wrangler,
or similar UI/dev-server app:

```sh
guard init
```

Inspect the current resolution state:

```sh
guard doctor
guard doctor pnpm --json
guard list profiles
guard list templates
guard daemon --port 8765
guard profile doctor --profile teams
guard diff-profile zoom teams
guard network-log /tmp/guard-network.jsonl
```

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

The local setup can install PATH shims in `~/.local/bin` so common dependency
and script runners are guarded in both interactive terminals and non-interactive
Codex-style shells. `guard` remains the only real executable. The tool-name
symlinks are just policy gates that dispatch back into `guard`.

Guarded shims:

```text
node pnpm npm python python3 pip pip3
```

Disabled shims:

```text
npx corepack deno
```

Escape hatches:

```sh
guard off npm i -g @openai/codex
command pnpm ...
command node ...
PNPM_GUARD_BYPASS=1 pnpm ...
NODE_GUARD_BYPASS=1 node ...
GUARD_SHIM_BYPASS=1 <tool> ...
```

Inside the configured managed root, unconfigured directories fail closed for
shimmed tools. Outside that root, the shims run the real tools normally.

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

## Commands

```text
guard [options] <command> [args...]
guard [options] -- <command> [args...]
guard [options]
guard off <command> [args...]
guard unprotected <command> [args...]
guard help
guard run <webex|teams|zoom> [args...]
guard doctor [tool] [--json]
guard audit [--json]
guard settings [--json]
guard tls status [--json]
guard scan npm [--dir DIR] [--include-node-modules] [--json]
guard app-summary --profile NAME [--json]
guard daemon [guardd options...]
guard ui [--dir DIR]
guard monitor-log [--json] [--limit N] [PATH]
guard profile add FIELD VALUE [--json]
guard profile remove FIELD VALUE [--json]
guard profile add-http-rule (--host HOST|--cidr CIDR) [--method METHOD] [--path PATH] [--json]
guard profile remove-http-rule (--host HOST|--cidr CIDR) [--method METHOD] [--path PATH] [--json]
guard profile add-raw-tcp (--host HOST [--resolve-at-launch]|--ip IP) --port PORT [--reason TEXT] [--json]
guard profile remove-raw-tcp (--host HOST [--resolve-at-launch]|--ip IP) --port PORT [--reason TEXT] [--json]
guard profile tls <enable|disable|status> [--json]
guard profile doctor [--json]
guard install-monitor [--dir DIR] [--force]
guard install-app <webex|teams|zoom> [--dir DIR] [--force]
guard install-app all [--dir DIR] [--force]
guard install-apps [--dir DIR] [--force]
guard discover [--profile NAME] [--report PATH] -- <command> [args...]
guard diff-profile OLD NEW [--json]
guard network-log PATH [--json]
guard list profiles [--json]
guard list templates [--json]
guard list domain-presets [--json]
guard setup [--bin-dir DIR] [--code-root DIR] [--shims|--no-shims] [--force] [--yes]
guard install [--bin-dir DIR] [--code-root DIR] [--no-shims] [--force]
guard init [template] [--force]
```

- `guard`: run a command inside the matched policy
- `guard help`: print CLI usage
- `--ask-network`: prompt before allowing unknown proxied network hosts for
  the current run
- `--deep-egress`: compatibility flag for the default `iron-proxy` backend
- `--daemon-policy`: route unknown proxied network decisions through `guardd`
  pending alerts for this run. Alias flags are `--guardd-policy` and
  `--use-guardd`
- `--deny-subprocesses`: deny child process execution by default for this run.
  Aliases are `--no-child-processes` and `--deny-children`
- `--allow-subprocesses`: force permissive child process execution for this
  run, overriding a strict profile. Aliases are `--allow-child-processes` and
  `--allow-children`
- `--allow-read PATH`, `--allow-write PATH`, `--deny-read PATH`, and
  `--deny-write PATH`: add one-run filesystem path rules
- `--allow-domain HOST` and `--deny-domain HOST`: add one-run domain rules
- Guard blocks common telemetry domains by default, including analytics,
  tag-manager, product analytics, session replay, and crash-reporting hosts.
  Explicit `--allow-domain HOST` or `network.allowedDomains` entries override
  those default denies. Use `--allow-telemetry-domains` to disable the default
  telemetry blocklist for one run, or `--block-telemetry-domains` to force it on
- `--allow-exec PATH`: add one executable to the one-run subprocess allowlist
- `--allow-risky-child-tools`: permit child executions of commonly abused tools
  such as `curl`, `wget`, `python`, `ruby`, `perl`, `osascript`, and `nc` for
  this run. Use `--block-risky-child-tools` to force the default blocklist back
  on if a profile disables it
- `--allow-loopback` and `--allow-loopback-port PORT`: add one-run loopback
  network exceptions
- `--no-network` and `--network-unrestricted`: force no egress or unrestricted
  egress for this run
- `--proxy-logs` and `--quiet-proxy-logs`: show or quiet proxy logs for this run
- `guard` with no command: show the resolved policy banner
- `guard run`: launch a built-in app profile by name
- `guard doctor`: inspect current resolution and profile state
- `guard audit`: print risky policy choices for the selected profile
- `guard settings`: print monitor, prompt, daemon, and TLS inspection settings
- `guard tls status`: print the effective TLS inspection policy for a profile
- `guard scan npm`: statically scan an npm project for URL and domain literals.
  The scanner skips `node_modules` and common build/cache folders by default;
  pass `--include-node-modules` when dependency code should be included.
- `guard app-summary`: print the permission summary used by native launchers
- `guard daemon`: run the local `guardd` prototype for health and recent event
  APIs
- `guard ui`: build, install, and start the native Guard menu-bar monitor
- `guard monitor-log`: summarize the persistent Guard event stream used by the
  native monitor
- `guard profile add` / `guard profile remove`: edit project-local profile
  array rules such as `network.allowedDomains` and `filesystem.denyRead`
- `guard profile add-http-rule` / `guard profile remove-http-rule`: edit
  `iron-proxy` HTTP method/path rules in the project profile
  JSON output includes stable rule IDs and metadata keys; project profiles store
  this in a backward-compatible top-level `ruleMetadata` sidecar.
- `guard profile add-raw-tcp` / `guard profile remove-raw-tcp`: edit structured
  `network.allowedRawTcp` rules for exact supported raw TCP exceptions
- `guard profile tls`: enable, disable, or inspect explicit project-local TLS
  inspection settings
- `guard profile doctor`: validate profile quality for CI/review
- `guard install-monitor`: build the native macOS monitor app
- `guard install-app`: build one native macOS `.app` launcher wrapper, or all
  wrappers with `guard install-app all`
- `guard install-apps`: build all native macOS launcher wrappers
- `guard discover`: run with temporary network ask/logging and write a
  discovery report
- `guard diff-profile`: compare two profile policy surfaces
- `guard network-log`: summarize guard proxy allow/deny decisions
- `guard list profiles`: list built-in profiles such as `zoom`, `teams`, and
  `webex`
- `guard list templates`: list project bootstrap templates for `guard init`
- `guard list domain-presets`: show denied-domain preset names and patterns
- `guard setup`: guided first-run or rerunnable install and managed-root
  configuration, including the current configured values
- `guard install`: install the entrypoint, optional shims, and user-local config
- `guard init`: create `.guard/guard.json` from a bundled template

## Native App Launchers

Install the local monitor app:

```sh
guard ui
```

This builds and starts `Guard Monitor.app` as a lightweight menu-bar utility.
It shows only the toolbar/status icon by default. On launch, the monitor
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
process lifecycle, sandbox profile, proxy startup, and network decision events
there as JSON lines. Override the location with `GUARD_STATE_DIR` or
`GUARD_EVENT_LOG` before launching guarded commands or installing the monitor.

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

The monitor UI is intentionally moving toward a Little Snitch-style native
workflow without adding packaging or signing requirements: the header shows
profile risk and rule status chips, a compact live allow/deny traffic graph, and
a Focus Top Host action that opens the Rules window filtered to the busiest recent
destination. Rules carry action, type, enabled state, and scope-risk labels so
broad host/domain grants are easier to spot before editing. The dedicated Rules
window supports multi-select edits, a Disable Visible bulk action, and
optimistic profile-version checks so stale UI edits reload instead of silently
overwriting newer CLI or daemon changes.

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
  and `deno` only where the native runtime supports it
- keep `npx` and `corepack` disabled by default because they are easy
  one-command remote execution paths
- use explicit `guard <tool> ...` for `make`, `just`, `go`, `cargo`, `uv`,
  `poetry`, `bun`, `yarn`, `gem`, `bundle`, `mvn`, and `gradle` when working in
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

`guard --daemon-policy <command>` is the daemon-backed variant. It forces
ask-style proxy decisions, writes `network.decisionMode: "guardd"` into the
temporary runtime config, and posts unknown destinations to `POST
/alerts/pending`. The guarded process waits until the alert is resolved through
`POST /alerts/:id/resolve` or `POST /alerts/decision`; unresolved or unreachable
daemon decisions are denied. This works with both the normal Guard proxy and
`guard --deep-egress` / `network.backend: "iron-proxy"`.

`network.allowLocalBinding` is intentionally loopback-only. It permits local dev
servers to listen on localhost without allowing direct outbound TCP, DNS, or
ICMP egress. For dev tools that need to call back into localhost helper
services, prefer exact `network.allowLoopbackPorts`.

Note: `network.allowLoopbackPorts` authorizes a localhost port number, not a
specific process. Only list ports that are stable and expected for the project;
if a different local service later binds the same port, the sandbox cannot
distinguish it from the intended helper.

Warning: `network.allowLoopbackHighPorts` is a compatibility fallback, not the
default recommendation. macOS sandbox profiles do not support compact port
ranges, so Guard must emit one rule per ephemeral port for `49152-65535`. That
keeps the boundary narrower than all localhost access, but it can make guarded
command startup noticeably slower and grants access to any loopback service in
that high-port range. Prefer exact `network.allowLoopbackPorts`, or use
`network.allowLoopbackListeningHighPorts` when the helper service is already
listening before the guarded command starts.

`network.allowLoopbackConnections` permits all localhost TCP ports and should be
treated as an escape hatch.

`guard` no longer depends on the external `srt` package. The current native
runtime uses macOS `sandbox-exec` directly and keeps the policy generation local
to this repo.

The native runtime now lives in:

- `lib/guard-manager.mjs`
- `lib/guard-utils.mjs`

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
