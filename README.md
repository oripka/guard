# guard

This repo contains the local `guard` runtime, installer, and reference
policies for running risky developer commands under a native macOS sandbox.

## Install

Requirements:

- macOS with the native `sandbox-exec` runtime
- Node.js 20 or newer
- `~/.local/bin` or another user-writable bin directory on `PATH`
- Xcode Command Line Tools only if you want optional native `.app` wrappers

Package-manager install from GitHub:

```sh
pnpm add -g github:<owner>/guard
guard setup
```

Or clone and link directly from the repo:

```sh
git clone https://github.com/<owner>/guard.git ~/src/guard
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

From a project that contains `.guard/guard.json`:

```sh
guard pnpm run dev
guard --ask-network pnpm run dev
```

Bootstrap a default project profile:

```sh
guard init
```

Inspect the current resolution state:

```sh
guard doctor
guard doctor pnpm --json
guard list profiles
guard profile doctor --profile teams
guard diff-profile zoom teams
guard network-log /tmp/guard-network.jsonl
```

Built-in app profiles can be launched from any directory:

```sh
guard run zoom
guard run teams
guard run webex
guard help
guard install-app webex
guard install-app teams
guard install-app zoom
guard install-apps
guard --profile zoom -- /Applications/zoom.us.app/Contents/MacOS/zoom.us
guard --profile teams -- "/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams"
guard --profile webex -- /Applications/Webex.app/Contents/MacOS/Webex
```

Or:

```sh
guard-zoom
guard-teams
guard-webex
```

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
guard [--profile NAME] [--ask-network] <command> [args...]
guard [--profile NAME] [--ask-network] -- <command> [args...]
guard [--profile NAME] [--ask-network]
guard help
guard run <webex|teams|zoom> [args...]
guard doctor [tool] [--json]
guard audit [--json]
guard app-summary --profile NAME [--json]
guard profile doctor [--json]
guard install-app <webex|teams|zoom> [--dir DIR] [--force]
guard install-app all [--dir DIR] [--force]
guard install-apps [--dir DIR] [--force]
guard discover [--profile NAME] [--report PATH] -- <command> [args...]
guard diff-profile OLD NEW [--json]
guard network-log PATH [--json]
guard list profiles [--json]
guard list domain-presets [--json]
guard setup [--bin-dir DIR] [--code-root DIR] [--shims|--no-shims] [--force] [--yes]
guard install [--bin-dir DIR] [--code-root DIR] [--no-shims] [--force]
guard init [template] [--force]
```

- `guard`: run a command inside the matched policy
- `guard help`: print CLI usage
- `--ask-network`: prompt before allowing unknown proxied network hosts for
  the current run
- `guard` with no command: show the resolved policy banner
- `guard run`: launch a built-in app profile by name
- `guard doctor`: inspect current resolution and profile state
- `guard audit`: print risky policy choices for the selected profile
- `guard app-summary`: print the permission summary used by native launchers
- `guard profile doctor`: validate profile quality for CI/review
- `guard install-app`: build one native macOS `.app` launcher wrapper, or all
  wrappers with `guard install-app all`
- `guard install-apps`: build all native macOS launcher wrappers
- `guard discover`: run with temporary network ask/logging and write a
  discovery report
- `guard diff-profile`: compare two profile policy surfaces
- `guard network-log`: summarize guard proxy allow/deny decisions
- `guard list profiles`: list built-in profiles such as `zoom`, `teams`, and
  `webex`
- `guard list domain-presets`: show denied-domain preset names and patterns
- `guard setup`: guided first-run or rerunnable install and managed-root
  configuration, including the current configured values
- `guard install`: install the entrypoint, optional shims, and user-local config
- `guard init`: create `.guard/guard.json` from a bundled template

## Native App Launchers

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

`guard --ask-network <command>` enables a per-run prompt for proxied network
requests that are not already matched by `network.allowedDomains` and are not
blocked by `network.deniedDomains`.

Approving a host allows that host for the rest of the current run only. Denying
it blocks that host for the rest of the current run. Non-interactive shells fail
closed instead of waiting for input.

When the guarded command is an interactive shell such as `bash` or `zsh`, guard
uses a macOS dialog for the prompt so the parent proxy process does not fight the
child shell for terminal control. Set `GUARD_ASK_NETWORK_UI=tty` to force the
terminal prompt, or `GUARD_ASK_NETWORK_UI=dialog` to force the dialog.

The same mode can be enabled in a profile:

```json
"network": {
  "ask": true,
  "allowedDomains": [],
  "deniedDomains": []
}
```

This applies to traffic that goes through guard's HTTP/SOCKS proxy support.
Direct raw TCP remains controlled by the native sandbox profile.

`network.allowLocalBinding` is intentionally loopback-only. It permits local dev
servers to listen on localhost without allowing direct outbound TCP, DNS, or
ICMP egress. For dev tools that need to call back into localhost helper
services, prefer exact `network.allowLoopbackPorts`. If a tool chooses random
local callback ports, `network.allowLoopbackHighPorts` permits only the macOS
ephemeral range `49152-65535`. `network.allowLoopbackConnections` permits all
localhost TCP ports and should be treated as an escape hatch.

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
```

Copy it to:

```text
.guard/guard.json
```
The template uses `${GUARD_PROJECT_DIR}`, so most projects do not need an
absolute local path.

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
