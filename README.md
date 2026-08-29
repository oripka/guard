# guard

`guard` runs local developer commands and selected macOS apps inside a reviewed
filesystem, subprocess, and network policy. It is an early alpha for local
developer workflows, not a production firewall or a system-wide Little Snitch
replacement.

Use it when opening an unfamiliar repo, installing dependencies, running a dev
server, launching a risky helper, or reviewing which local files and network
destinations a command should be allowed to reach.

## Quick Start

Install the CLI:

```sh
curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh | sh
guard doctor
```

Create a project profile and run commands through Guard:

```sh
cd ~/code/my-project
guard init
guard pnpm install
guard --ask-network pnpm run dev
guard node scripts/build.mjs
```

Launch built-in macOS app profiles:

```sh
guard run zoom
guard run teams
guard run webex
```

`guard`, `guard --ask-network`, and
`guard --deep-egress --ask-network` are daemon-free per-run flows. They do not
require `guardd`, Guard.app, a launch agent, or a Network Extension.

## Account Sessions

Daemon/UI mode can monitor machine-local developer account sessions from
`~/.config/guard/config.json` without adding provider behavior to Guard core:

```sh
guard account setup
guard account list
guard account refresh
guard account login codex-mac
```

The native Accounts window shows sign-in state, locally observed last use,
expiry when exposed, and a supervised Login Again action. Provider-contacting
checks are manual by default. Ordinary guarded runs remain independent of this
feature. See [Account session monitoring](docs/account-monitoring.md).

## Project Config

Guard reads `.guard/guard.json` from the current project. Profile files are
strict JSON. A small Node project can start with:

```json
{
  "imports": ["node-app-defaults"],
  "network": {
    "backend": "iron-proxy",
    "ask": true,
    "allowedDomains": ["registry.npmjs.org"],
    "httpRules": [
      {
        "host": "api.openai.com",
        "methods": ["POST"],
        "paths": ["/v1/responses"]
      }
    ]
  },
  "filesystem": {
    "allowRead": ["${GUARD_PROJECT_DIR}", "${GUARD_RUN_DIR}"],
    "allowWrite": ["${GUARD_PROJECT_DIR}", "${GUARD_RUN_DIR}"],
    "denyWrite": [".env", ".env.*", "secrets/", "*.key", "*.pem"]
  },
  "process": {
    "denyByDefault": true,
    "allowedExecutables": [
      "/usr/bin/env",
      "/bin/sh",
      "/opt/homebrew/bin/node",
      "/opt/homebrew/bin/pnpm",
      "${GUARD_PROJECT_DIR}/node_modules/.bin/*"
    ]
  }
}
```

Useful profile edits:

```sh
guard profile add network.allowedDomains registry.npmjs.org
guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
guard profile add filesystem.allowRead ./fixtures
guard profile add filesystem.allowWrite ./tmp
guard profile doctor
```

## Feature Guides

- [pnpm and supply-chain installs](docs/pnpm-supply-chain.md)
- [Network policy and proxying](docs/network-policy.md)
- [Secret injection](docs/secret-injection.md)
- [PATH shims](docs/shims.md)
- [Subprocess policy](docs/subprocess-policy.md)
- [Filesystem policy](docs/filesystem-policy.md)
- [Project profiles and templates](docs/project-profiles.md)
- [Experimental native macOS app profiles](docs/native-apps.md)
- [guardd daemon](docs/guardd.md)
- [Guard UI](docs/ui.md)
- [Account session monitoring](docs/account-monitoring.md)
- [TLS inspection scaffold](docs/tls-inspection-policy-scaffold.md)
- [Network Extension roadmap](docs/network-extension-roadmap.md)

## What Guard Protects

Default project profiles deny broad reads from user homes, mounted volumes,
`/Applications`, `/cores`, and `/home`; reopen only the current project and
Guard's per-run directory; restrict package installs to package artifacts; block
common secret writes; route cooperative network clients through HTTP/SOCKS proxy
settings; and optionally make child-process execution explicit.

Guard does not protect apps that are not launched through Guard unless they
voluntarily use Guard's proxy environment. The daemon, native monitor, and
Network Extension work are prototype/planning surfaces until they are signed,
notarized, and installer-ready.

## Install Notes

The installer places Guard under `~/.local/guard`, links `guard` and bundled
`iron-proxy` into `~/.local/bin`, and runs onboarding setup. To install a
specific release or replace an existing release:

```sh
GUARD_VERSION=v0.2.0 sh -c "$(curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh)"
GUARD_FORCE=1 sh -c "$(curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/install.sh)"
```

Uninstall:

```sh
curl -fsSL https://raw.githubusercontent.com/oripka/guard/main/uninstall.sh | sh
```

Developer checkout:

```sh
guard setup --yes --code-root ~/code --bin-dir ~/.local/bin
guard install --code-root ~/code
```

Linux support is experimental and limited to the current `bubblewrap` backend.
