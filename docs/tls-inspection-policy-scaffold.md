# TLS Inspection Policy Scaffold

Guard's current TLS inspection support is a per-run scaffold built around the
`iron-proxy` backend. It is now visible through `guard tls status`,
`guard settings`, profile-local `guard profile tls ...` commands, and the
native monitor settings surface.

## Current Runtime Boundary

When a profile sets `network.backend` to `iron-proxy`, Guard starts a local
`iron-proxy` instance for the guarded run, generates a short-lived CA under the
run directory, writes an `iron-proxy` config with that CA, and injects proxy and
CA environment variables into the sandboxed process.

The current policy surface is:

- `network.backend: "iron-proxy"` enables deep proxy egress for the run.
- `network.ask: true` enables per-run prompts for unmatched proxied requests.
- `network.allowedDomains` allows host/domain-level proxied requests.
- `network.httpRules` allows method/path-scoped HTTP rules.
- `guard --deep-egress --ask-network` can force the same backend for a run.

The CA is deliberately run-scoped. Guard injects the generated certificate via
common trust environment variables such as `NODE_EXTRA_CA_CERTS`,
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO`.
This keeps simple per-run mode daemon-free and avoids requiring a globally
trusted Guard CA.

## Policy Semantics

Deep HTTP/TLS inspection should remain distinct from coarse destination
visibility:

- The Network Extension scaffold should normalize app/process/destination flow
  events and make only coarse allow/deny decisions.
- `iron-proxy` should own decrypted HTTP-aware decisions when traffic is routed
  through the proxy and the guarded process trusts the run CA.
- A single user-facing rule model should explain whether a decision was made at
  the filesystem, destination-network, or HTTP-inspection layer.

Rules broader than the exact observed request should preview their consequence
before they are committed. For example, allowing `POST
api.openai.com/v1/responses` is narrower than allowing all proxied requests to
`api.openai.com`.

## Settings And Status

Use these surfaces:

- `guard tls status [--json]` reports the selected profile's effective TLS
  inspection state.
- `guard settings [--json]` reports monitor event paths, ask UI mode, daemon
  defaults, and TLS inspection mode.
- `guard profile tls enable|disable|status [--json]` persists an explicit
  project-local `network.tlsInspection` setting.
- `guard monitor-log` shows recorded proxy startup events, including the
  run-scoped CA path when `iron-proxy` starts.
- `guard daemon` exposes the prototype health, recent event, profile, policy,
  and template API.

Example profile setting:

```json
"network": {
  "backend": "iron-proxy",
  "tlsInspection": {
    "enabled": true,
    "mode": "ephemeral-run-ca",
    "caScope": "guarded-process-env",
    "userApprovalRequired": true
  }
}
```

## Test Coverage

Current tests cover `guard settings --json`, `guard tls status --json`, and
profile-local TLS setting mutation. Future Network Extension tests should cover
installed/enabled/degraded system-extension states once Apple signing and
System Settings approval are available.
