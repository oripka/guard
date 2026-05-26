# Network Policy

Network policy controls which destinations a guarded command can reach and how
HTTP/S requests are reviewed.

## Benefit

Developer tools often fetch packages, call APIs, open local callbacks, and run
dev servers. Guard makes those destinations explicit, blocks direct raw egress
where the backend supports it, and routes cooperative clients through local
HTTP/SOCKS proxy settings.

## Defaults

The Node defaults allow npm registry traffic and local development binding, but
do not grant arbitrary outbound network access. Guard defaults guarded runs to
the `iron-proxy` backend so HTTP decisions can include host, method, path, and
TLS state.

Guard sets proxy variables for common clients:

- `HTTP_PROXY`, `HTTPS_PROXY`, and lowercase variants.
- npm/yarn/pnpm proxy config variables.
- `ALL_PROXY`, `GUARD_SOCKS_PROXY`, Git/Rust/Go/rsync SOCKS-style variables.
- `GUARD_SSH_PROXY_COMMAND` and `GIT_SSH_COMMAND` for SSH-over-SOCKS.

## Project Config

```json
{
  "network": {
    "backend": "iron-proxy",
    "ask": true,
    "learnHttpRules": true,
    "allowedDomains": ["registry.npmjs.org"],
    "deniedDomains": ["telemetry.example.com"],
    "httpRules": [
      {
        "host": "api.openai.com",
        "methods": ["POST"],
        "paths": ["/v1/responses"]
      }
    ],
    "allowedRawTcp": [
      {
        "host": "localhost",
        "resolveAtLaunch": true,
        "port": 8976,
        "reason": "local OAuth callback"
      }
    ]
  }
}
```

Run:

```sh
guard --ask-network pnpm run dev
guard profile add network.allowedDomains registry.npmjs.org
guard profile add-http-rule --host api.openai.com --method POST --path /v1/responses
guard profile add-raw-tcp --host localhost --resolve-at-launch --port 8976 --reason "local OAuth callback"
```

## Policy Types

`network.allowedDomains` is for proxy-aware clients. Direct raw sockets remain
constrained so a process cannot bypass domain policy by opening its own TCP
connection.

`network.httpRules` is for deep HTTP policy through `iron-proxy`: host, method,
path, selected headers, and TLS inspection state.

`network.allowedRawTcp` is for exact direct TCP exceptions. In the current
macOS `sandbox-exec` backend this is limited to loopback destinations. Use the
SOCKS/SSH proxy path for external SSH until the Network Extension backend owns
exact external destination rules.

## What It Protects

Network policy protects against:

- dependency installers calling unexpected hosts.
- API clients reaching broader paths than reviewed.
- direct raw egress bypassing proxy-based domain policy.
- accidental telemetry or update checks from high-risk repos.
- SSH/Git/package helper flows that need a SOCKS-compatible proxy path.

## Global Defaults

Useful environment defaults:

```sh
GUARD_ASK_NETWORK_UI=native
GUARD_EVENT_LOG=~/Library/Application\ Support/guard/events.jsonl
GUARD_TEMP_HTTP_DECISIONS=~/Library/Application\ Support/guard/temporary-http-decisions.json
GUARD_IRON_PROXY_BIN=/path/to/iron-proxy
```

Project profiles should hold durable allow/deny rules. Use global environment
settings only for local UI/runtime preferences.
