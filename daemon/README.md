# guardd prototype

This directory contains a bounded local daemon scaffold. It is intentionally
separate from the current per-run `guard` CLI path.

Run it with:

```sh
node daemon/guardd.mjs --event-log ~/Library/Application\ Support/guard/events.jsonl
```

Environment defaults:

- `GUARD_EVENT_LOG` overrides the JSONL event log path.
- `GUARD_STATE_DIR` changes the default state directory.
- `GUARDD_HOST`, `GUARDD_PORT`, `GUARDD_MAX_EVENTS`, and `GUARDD_POLL_MS`
  configure the prototype daemon.
- `GUARDD_POLICY_ROOT` points at a profile root containing `.guard/*.json`
  profiles. If unset, `GUARD_PROJECT_DIR` is used when present; otherwise the
  daemon uses the Guard state directory, normally
  `~/Library/Application Support/guard`, as the global profile root.
- `GUARDD_REPO_ROOT` points at the Guard repository root used for built-in
  `profiles/*.json` and `templates/*/guard.json`.
- `GUARDD_API_TOKEN` enables simple local API authentication. Send it as
  `Authorization: Bearer <token>` or `X-Guard-Token: <token>`.
  Status endpoints expose only token metadata such as length and a short
  SHA-256 fingerprint, never the configured secret.
- `GUARDD_TOKEN_KEYCHAIN=1` reads the API token from macOS Keychain at startup
  when no `--api-token` / `GUARDD_API_TOKEN` value is supplied. The default
  item is service `com.guard.guardd.api-token` and the current user as account;
  override with `GUARDD_TOKEN_KEYCHAIN_SERVICE` and
  `GUARDD_TOKEN_KEYCHAIN_ACCOUNT`.

When listening outside loopback, `guardd` requires `--api-token` or
`GUARDD_API_TOKEN`. The default listener remains `127.0.0.1`.

Read-only HTTP API:

- `GET /health` returns daemon status, API version, state directory, event log
  path, policy/template paths, auth mode, tail state, persisted cursor metadata,
  restart recovery status, and retention/truncation metadata. Legacy top-level
  fields such as `eventLogPath` remain for current clients.
- `GET /state` returns the same daemon state in a structured shape with
  `paths`, `auth`, and `tail` sections for native UI health checks. The tail
  section includes `metadataPath`, `offset`, `recovery`, and `retention` so a
  restarted UI can distinguish a healthy cursor recovery from a cold tail scan
  or a recently truncated log. The `auth.token` section includes runtime token
  metadata, rotation status, and a Keychain-ready descriptor without invoking
  the macOS Keychain.
- `GET /auth/token` returns runtime token status: whether authentication is
  configured, a short SHA-256 fingerprint, length, rotation metadata, and a
  macOS Keychain descriptor. It never returns the token secret.
- `GET /tls/ca` returns TLS CA lifecycle metadata: intended local state paths,
  whether files already exist, current lifecycle state, and explicit
  `installedGlobally: false` / `globalTrustManaged: false` status. It also
  reports private-key filesystem protection metadata and a Keychain-ready
  descriptor. This daemon endpoint does not install or trust a CA globally and
  does not invoke the system Keychain.
- `GET /tls/cert?host=api.example.com` returns the cached leaf certificate
  metadata for one host, including artifact paths and the active local CA
  lifecycle.
- `GET /tls/status` returns user-facing TLS trust diagnostics: CA lifecycle,
  cached host-certificate inventory, expired certificate counts, local trust
  environment variables, and findings. It always reports
  `globalTrustManaged:false` because this feature build does not alter the
  macOS trust store. The native monitor Settings window uses this endpoint as the
  source for guided trust onboarding, rotation/recovery diagnostics, CA artifact
  paths, and local-only trust status.
- `GET /security/status` checks the local daemon security posture: API token
  enforcement, state directory permissions, event/policy path write exposure,
  runtime-token metadata, TLS CA private-key mode, and Keychain-ready
  descriptors for future production secret storage.
- `GET /extension/sync` returns the current NetworkExtension app-group sync
  state: manifest, policy/event/heartbeat paths, sequence, and generated-file
  flags. It also reports the current policy digest, whether that digest matches
  the manifest, and whether the manifest has been invalidated.
- `GET /events?limit=100&type=network.decision` returns recent parsed JSONL
  events, newest first.
- `GET /events/query?limit=100&type=network.decision&host=api.example.com`
  scans a bounded tail of the persisted JSONL log, not only the in-memory
  recent buffer. It supports `type`, `host`, `profile`, `result`, `contains`,
  `since`, `limit`, and `maxBytes` filters. Responses include match summaries
  by type, host, profile, and result, plus invalid/tamper line counters for the
  scanned byte range.
- `GET /events/index` returns the daemon-maintained durable event index under
  the state directory, with counts by type, host, profile, result, alert
  decisions, top-N summaries, and the last persisted rebuild metadata. The
  rebuild metadata records the event log identity, scanned bytes/lines, valid
  lines, invalid JSON lines, unsupported/missing-schema tamper lines, observed
  event schema versions, and rebuild timing.
- `GET /events/integrity` scans the bounded persisted JSONL range used for UI
  diagnostics and returns `ok`, file identity, scanned digest, schema-version
  distribution, invalid-line counters, tamper-line counters, and sample issues.
- `GET /alerts?limit=50` is the event-query view filtered to
  `guard.alert.decision`, suitable for native alert history panels.
- `GET /alerts/pending?limit=50` returns the durable alert queue with
  `pendingCount`, expiry metadata, and optional `status=pending|resolved|expired`
  filtering for monitor controls.
- `GET /policy?profile=guard` returns the effective read-only profile config,
  with profile imports merged using the same JSON semantics as the CLI. The
  top-level `version`/`hash` fields refer to the selected profile file for
  write checks; `effectiveVersion`/`effectiveHash` refer to the merged config.
- `GET /profiles` lists project profiles from `.guard/*.json` and built-in
  profiles from `profiles/*.json`. Profile list entries include `version`,
  `hash`, and `shortHash` fields derived from stable profile JSON.
- `GET /profiles/:name` returns the raw selected project/global or built-in
  profile JSON. Writable profiles under the configured profile root win when
  names overlap. The response includes the same stable version/hash fields and
  an `ETag` header.
- `GET /templates` lists bundled project templates.
- `GET /templates/:name` returns raw bundled template JSON.
- `GET /templates/:name/preview?profile=guard` previews applying a bundled
  template to a project profile without writing. It returns the target path,
  whether the profile already exists, existing/template versions, and a compact
  effective summary based on merging the existing project config with the
  template JSON.

Authenticated write API:

- `POST /policy/evaluate` evaluates the effective profile through the shared
  Guard policy evaluator. Body:
  `{"profile":"guard","host":"api.example.com","method":"POST","path":"/v1"}`.
  It returns `decision.allowed`, `reason`, `ruleId`, and the matched policy
  field/value where available. This is read-like but token-protected because it
  uses `POST` and can expose policy details.
- `POST /extension/sync` writes the app-group sync protocol consumed by the
  NetworkExtension scaffold. Body: `{"profile":"guard","mode":"permissive-fallback"}`.
  It writes a manifest, effective policy snapshot, policy SHA-256 digest,
  event-log path, heartbeat, cache staleness limits, backpressure limits, and
  fallback behavior. It also emits a `network.extension.sync` audit event.
- `POST /extension/sync` with `{"action":"invalidate","reason":"..."}` marks
  the current manifest invalid and advances its sequence. The scaffolded
  extension treats this as stale sync state and follows strict fallback
  behavior.
- `POST /tls/ca` manages local CA artifacts without touching the macOS trust
  store. Body `{"action":"generate","days":30}` creates a local self-signed CA
  certificate/key/bundle under the daemon state directory. `{"action":"rotate"}`
  archives existing artifacts and creates a new CA. `{"action":"revoke"}` marks
  metadata revoked. Every action emits `tls.ca.changed` with
  `globalTrustManaged:false`. These actions are the monitor's TLS onboarding
  and recovery controls; they never install global trust.
- `POST /tls/cert` issues or reuses a host certificate signed by the local
  Guard CA. Body: `{"host":"api.example.com","days":7}`. Add
  `"force":true` to regenerate the cached leaf. Certificates are stored under
  the daemon state directory and emit `tls.cert.changed`; the endpoint still
  never touches the macOS trust store.
- `POST /alerts/decision` records a guarded-run network user decision. Body:
  `{"profile":"guard","host":"api.example.com","action":"allow","duration":"once"}`.
  `action` may be `allow` or `deny`; `duration` may be `once`, `session`, or
  `forever`. `forever` persists the corresponding allow/deny domain rule using
  the same optimistic version checks as profile rule edits. Non-persistent
  decisions are audit events only.
- `POST /alerts/pending` enqueues a live alert for UI review. Body:
  `{"profile":"guard","host":"api.example.com","port":443,"method":"POST","path":"/v1/responses","timeoutMs":120000}`.
  The response includes an alert `id`, `status`, `createdAt`, `expiresAt`, and
  `timeoutMs`; expired alerts emit `guard.alert.expired` when the queue is next
  read or resolved.
- `guard --daemon-policy <command>` uses this endpoint as an opt-in CLI bridge:
  the per-run proxy enqueues unknown destinations, waits for the alert to be
  resolved by Guard.app or another daemon client, and denies the request if
  `guardd` is unreachable or the alert times out. This does not change the
  default daemon-free `guard` and `guard --ask-network` behavior.
- `POST /alerts/:id/resolve` resolves a pending alert through the same decision
  path as `/alerts/decision`. Body: `{"action":"allow","duration":"session"}`.
  Successful resolution emits both `guard.alert.decision` and
  `guard.alert.resolved`; stale or expired alert IDs return `404` or `409`
  without writing a decision.
- `POST /auth/token/rotate` rotates the configured API token for the current
  `guardd` process only. It requires the existing token, must be called from a
  loopback client, accepts `{"newToken":"..."}` with at least 20 characters or
  generates a random token when omitted, and emits
  `daemon.auth.token.rotated`. The new token is returned once by default so the
  caller can update its session; pass `{"returnToken":false}` to suppress that,
  or `{"persist":true}` / `{"storage":"macos-keychain"}` to write it through
  `/usr/bin/security add-generic-password -U`.
- `POST /auth/token/persist` writes the current runtime token to macOS Keychain
  using the descriptor returned by `GET /auth/token`.
- `POST /profiles/:name/rules` adds or removes rules in the configured profile
  root. If only a built-in profile exists, `guardd` first materializes a
  writable copy under `<policyRoot>/.guard/<name>.json`. Body:
  `{"action":"add","field":"network.allowedDomains","value":"api.example.com"}`
  or `{"action":"add","field":"network.httpRules","rule":{"host":"api.example.com","methods":["POST"],"paths":["/v1/*"]}}`.
  `action` may also be `disable` or `enable`. Disabled rules are removed from
  the active rule array and retained in `ruleMetadata` with `disabled: true`
  and the normalized rule value for review/editing.
- `POST /profiles/:name/tls` updates explicit TLS inspection state in the
  configured writable profile. Body: `{"enabled":true}`. Successful TLS changes
  append both the normal `policy.changed` event and a TLS-specific
  `tls.changed` event with before/after state and `globalTrustManaged: false`.
- `POST /events/truncate` truncates the local JSONL event log in a bounded way.
  Body: `{"keepBytes":0}` or a value up to `1048576`. The endpoint appends a
  `daemon.log.truncated` audit event after rewriting the file and persists the
  retention metadata under the daemon state directory.
- `POST /templates/:name/preview` is the body-based form of the preview
  endpoint. Body: `{"profile":"guard"}`. It does not mutate profile files and
  does not append a `policy.changed` audit event.
- `POST /templates/:name/apply` writes a bundled template to the project
  profile. Body: `{"profile":"guard","force":false}`.

Write endpoints require `GUARDD_API_TOKEN` / `--api-token` even on loopback.
Every successful mutation appends a `policy.changed` event to the Guard JSONL
event log.

Write endpoints accept an optional optimistic concurrency check using an
`If-Match` header or body field named `ifMatch`, `version`, or
`profileVersion`. Use the `version` value returned by `GET /profiles/:name` or
`GET /policy?profile=name`. If the current project profile version differs,
`guardd` returns `412` with `error: "version_mismatch"`. `If-Match: *` keeps the
old unconditional-write behavior.

This prototype exposes a bounded recent-event buffer through `GET /events` and
also maintains a durable event index for history summaries. It persists daemon
metadata under `$GUARD_STATE_DIR/daemon-state.json` by default using storage
schema version 2 while preserving event schema version 1. On restart, `guardd`
recovers the prior event cursor when the JSONL file identity still matches,
ingests events appended while it was offline, and otherwise scans a bounded tail
of the log so recent events remain visible to the UI. Startup also rebuilds the
durable index and records rebuild metadata so native UI diagnostics can
distinguish a clean index from one rebuilt over malformed or unsupported JSONL
rows. Invalid JSON rows and missing/unsupported event schema rows are counted
separately and excluded from the recent buffer and index. The metadata also
records the last retention/truncation operation for health checks. It does not
own launch agents or Network Extension lifecycle yet. The native monitor can
start a temporary foreground `guardd` with either the selected project profile
root or the global app-support profile root and stop that child process, but
that is intentionally separate from production launchd packaging/signing.
