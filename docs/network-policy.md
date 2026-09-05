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
- real API tokens being exposed to a guarded workload when paired with
  [secret injection](secret-injection.md).
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

## Backend compatibility requirements

## Network Policy Requirements

Guard has three intentionally different egress mechanisms. Keep their contracts
separate in code, docs, UI, and tests:

- `network.allowedDomains`: domain allowlist for traffic that cooperates with
  Guard's per-run proxy environment. The sandbox should still block direct raw
  egress so clients cannot bypass domain policy by opening sockets themselves.
- `network.httpRules`: deep HTTP policy for the `iron-proxy` backend. This is
  the place for host/domain, method, path, header, and TLS inspection behavior
  when traffic can be routed through the proxy.
- `network.allowedRawTcp`: exact IP:port sandbox egress exceptions for tools
  that cannot reasonably use the proxy path. In the current `sandbox-exec`
  backend this is limited to loopback destinations because macOS rejects exact
  external `remote ip "x.x.x.x:port"` filters; use the SOCKS/SSH proxy path for
  external SSH until a Network Extension backend owns exact destination rules.

`allowedRawTcp` rules must be narrow and reviewable:

- Accept `{ "ip": "127.0.0.1", "port": 8976 }` or equivalent loopback
  addresses for explicit addresses in the per-run sandbox backend.
- Accept `{ "host": "localhost", "resolveAtLaunch": true, "port": 8976 }`
  when a profile author deliberately chooses DNS resolution at run startup.
- Reject host rules that omit `resolveAtLaunch: true`; a hostname in a sandbox
  `remote ip` rule would otherwise be misleading and fail open or fail closed in
  ways users cannot reason about.
- Resolve host rules once per guarded run, emit an event containing the rule ID,
  host, port, resolved addresses, and reason, then render exact `ip:port`
  sandbox rules where the active backend supports that destination class.
- Reject exact external raw TCP in the current `sandbox-exec` backend with a
  clear error that points users to `GUARD_SSH_PROXY_COMMAND`, `GIT_SSH_COMMAND`,
  or the future Network Extension backend.
- Do not support wildcard ports, raw DNS egress, raw ICMP, or CIDR-wide direct
  TCP in the per-run sandbox path until there is a stronger product reason and
  matching UI/audit language.

The normal Guard backend and `iron-proxy` backend must expose the same
client-facing proxy contract:

- `HTTP_PROXY`, `HTTPS_PROXY`, lowercase variants, npm/yarn/pnpm proxy env, and
  other HTTP-aware variables point at the per-run HTTP proxy.
- `ALL_PROXY`, lowercase variant, FTP/Git/Rust/Go/rsync SOCKS-style variables,
  and `GUARD_SOCKS_PROXY` point at the per-run SOCKS listener.
- `GUARD_SSH_PROXY_COMMAND` contains an `ssh_config`-compatible
  `ProxyCommand`, and `GIT_SSH_COMMAND` wraps that command for Git over SSH.
- Helper scripts should read `GUARD_SOCKS_PROXY` or
  `GUARD_SSH_PROXY_COMMAND` rather than hardcoding backend internals.

PacketSafari-style helper requirements should be represented as ordinary
project profile rules: allow read/write for the specific PCAP folder, allow the
specific SSH key or ssh-agent socket/known_hosts path needed by the workflow,
and prefer proxy-routed SSH through the SOCKS environment. Add
`allowedRawTcp` only when the helper cannot use SSH `ProxyCommand` or SOCKS.

User-facing model:

- Profiles: Node app, Cloudflare Wrangler, Zoom, Teams, Webex, unknown repo,
  AI coding agent, and other reusable app/project templates.
- Rules: allow domain, deny domain, allow HTTP path, allow local filesystem
  path, deny secret files, allow once, allow until quit, and persistent allow or
  deny.
- Live Monitor: group activity by app, project, profile, process, destination,
  and rule outcome; clearly distinguish allowed, denied, inspected, direct, and
  proxied traffic.
- Alert Popup: show specific decisions such as `node` wanting to `POST` to
  `api.openai.com/v1/responses`, with actions like Allow Once, Allow Path,
  Allow Domain, Deny, and Open Rules.
- Templates: reusable policy packs for workflows such as Node package install,
  Vite dev server, OpenAI API client, Cloudflare deploy, video calls, and
  high-risk repo exploration.
- Settings: proxy CA status, Network Extension status, default deny behavior,
  log retention, profile storage, privacy controls, update checks, and
  diagnostics export.
