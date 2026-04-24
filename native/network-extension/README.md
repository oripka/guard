# Guard Network Extension Scaffold

Guard does not ship a runnable signed Network Extension bundle yet. The current
desktop app uses the local sandbox runner, Guard's proxy, and `iron-proxy` HTTP
policy prompts. This folder contains the source and entitlement scaffolding that
should be imported into a containing Xcode app target once Apple Developer
Network Extension capabilities are available.

The macOS provider scaffold is a transparent user-approved content filter shape.
It is feature code only: this folder does not add packaging, signing,
notarization, entitlement approval, or System Extension installation behavior.

## guardd Sync Protocol

The preferred local development path is a daemon-written app-group sync
manifest. `guardd` writes it through `POST /extension/sync`:

```json
{
  "syncVersion": 1,
  "sequence": 12,
  "generatedAt": "2026-04-24T12:00:00Z",
  "profile": "guard",
  "policyDigest": "sha256:...",
  "invalidatedAt": null,
  "invalidateReason": "",
  "maxPolicyAgeSeconds": 30,
  "maxEventBacklogBytes": 1048576,
  "fallback": {
    "unavailable": "permissive-fallback",
    "stalePolicy": "permissive-fallback",
    "eventBackpressure": "allow-with-backpressure-event"
  },
  "paths": {
    "policyPath": ".../network-extension/policy.json",
    "eventLogPath": ".../network-extension/events.jsonl",
    "heartbeatPath": ".../network-extension/heartbeat.json"
  }
}
```

The provider locates the manifest at `GUARD_NE_SYNC_MANIFEST_PATH` or app-group
storage under `Library/Application Support/Guard/network-extension/manifest.json`.
It checks the manifest on each new flow and invalidates cached policy when the
manifest modification time, policy path, or sequence changes. The provider
verifies the policy file's SHA-256 digest when `policyDigest` is present, treats
`invalidatedAt` as an explicit stale-sync signal, and recomputes policy
freshness even when the policy file itself has not changed, so
`maxPolicyAgeSeconds` can move a previously valid snapshot into stale fallback.

If the manifest temporarily disappears or cannot be parsed after a policy was
loaded, the provider keeps the last usable snapshot instead of immediately
dropping to no-policy behavior. Decision events and heartbeats expose this as
`fallbackReason: "sync-reconnecting"`, `"sync-unavailable"`, or
`"manifest-load-error"` depending on how long the sync channel has been gone.
If no policy has ever loaded, the manifest `fallback.unavailable` mode decides
whether unavailable sync is permissive or strict.

## Policy Snapshot

`GuardNetworkExtensionProvider` loads a JSON policy snapshot when the filter
starts and reloads it when the file modification time, manifest sequence, or
manifest policy path changes. The path is:

1. `GUARD_NE_POLICY_PATH`, when present in the provider environment.
2. The daemon sync manifest's `paths.policyPath`, when available.
3. App-group storage at
   `Library/Application Support/Guard/policy.json` under
   `GUARD_APP_GROUP_ID`.
4. The entitlement-template app group `TEAMID.dev.guard` when
   `GUARD_APP_GROUP_ID` is not set.

The expected snapshot shape matches existing Guard profiles:

```json
{
  "profile": "node-app",
  "projectDir": "/path/to/project",
  "network": {
    "backend": "iron-proxy",
    "allowedDomains": ["api.example.com", "*.example.net"],
    "deniedDomains": ["tracker.example.com"],
    "tlsInspection": {
      "enabled": true,
      "mode": "ephemeral-run-ca",
      "caScope": "guarded-process-env",
      "userApprovalRequired": true,
      "allowWithoutInspection": true,
      "failClosedWithoutDecryption": false,
      "inspectHosts": ["api.example.com"],
      "excludeHosts": ["updates.example.com"]
    },
    "httpRules": [
      {
        "host": "api.example.com",
        "methods": ["POST"],
        "paths": ["/v1/*"],
        "headers": { "content-type": "application/json" },
        "action": "allow"
      }
    ]
  }
}
```

`metadata.profile` and `metadata.projectDir` are also accepted for snapshots
written by a future daemon. If no snapshot is available, the provider allows the
flow and emits `reason: "policy-load-error"` or `reason: "no-policy"` so the UI
can show degraded enforcement instead of silently failing closed.

When `fallback.unavailable` is `"strict-deny"`, missing policy drops flows.
When `fallback.stalePolicy` is `"strict-deny"`, a loaded but stale policy drops
flows with `reason: "stale-policy"`.

## Decisions

The scaffold makes coarse flow decisions and emits TLS-inspection handoff
metadata:

- `network.deniedDomains` is checked first and drops matching hosts.
- `network.httpRules` are applied when HTTP request metadata is available.
  Matching rules allow by default; a rule with `"action": "deny"` drops. When
  HTTP metadata is available and rules exist, non-matching requests drop with
  `httpRules-default-deny`.
- HTTPS flows with `network.tlsInspection.enabled`, `backend: "iron-proxy"`, or
  matching `httpRules` are classified as TLS inspection candidates. If the flow
  already exposes request metadata, the provider emits a
  `decrypted-request-metadata-available` classification and can apply
  `httpRules` directly.
- HTTPS socket flows without decrypted request metadata are classified as
  `https-needs-proxy-decrypt` when deep HTTP rules exist. The provider requests
  an outbound data peek, parses the TLS ClientHello when visible, records SNI
  and TLS record version, and emits a handoff decision for `guardd`/Monitor.
- `tlsInspection.inspectHosts` limits TLS classification to matching hosts, and
  `tlsInspection.excludeHosts` records an explicit passthrough exclusion.
- `tlsInspection.allowWithoutInspection` defaults to `true` in this scaffold.
  Setting both `allowWithoutInspection: false` and
  `failClosedWithoutDecryption: true` drops HTTPS flows that require decrypted
  HTTP policy but only socket/TLS metadata is available.
- `network.allowedDomains` allows matching hosts.
- If `allowedDomains` is non-empty and no allow rule matched, the flow drops
  with `default-deny`.
- If the snapshot has no restrictive network policy, the flow allows with
  `default-allow`.

The provider does not terminate TLS, install a CA, modify proxy settings, or
decrypt arbitrary socket flows. Decrypted HTTP policy remains in Guard's proxy
and `iron-proxy`; this Network Extension layer is for app/process/destination
enforcement, bypass detection, TLS metadata capture, and explicit handoff events
when HTTPS traffic needs proxy-routed decryption.

## Monitor Events

The provider appends JSONL monitor events to:

1. `GUARD_NE_EVENT_LOG_PATH`, when present in the provider environment.
2. App-group storage at
   `Library/Application Support/Guard/network-extension-events.jsonl`.

Decision events use the same schema family as the current runner and daemon:

- `backend: "network-extension"`
- `schemaVersion: 1`
- `type: "network.decision"`
- `profile`, `projectDir`, `host`, `port`, `protocol`, `direction`
- `method`, `path`, and `url` when available
- `appBundleIdentifier`, `processPath`, and `pid` when available
- `allowed`, `reason`, `ruleId`
- `policyPath`, `policyLoaded`, and `policyLoadError` for degraded-state UI
- `policySequence`, `policyStale`, and `fallbackReason` for sync health UI

TLS inspection handoff events use the same policy metadata and add:

- `type: "network.tlsInspection.request"` when a new HTTPS flow is identified
  as needing TLS/deep HTTP handling.
- `type: "network.tlsInspection.decision"` after the provider observes the
  requested outbound bytes.
- `classification`, such as `https-needs-proxy-decrypt`,
  `decrypted-request-metadata-available`, `https-client-hello-observed`,
  `https-client-hello-unavailable`, or `tlsInspection-excluded-host`.
- `mode`, `caScope`, `trustedBy`, `userApprovalRequired`,
  `requiresDataPeek`, `decryptedRequestAvailable`, `httpRulesCount`, and
  `candidateRuleIds`.
- `sni`, `tlsVersion`, and `clientHelloOffset` when the outbound data contains
  a parseable TLS ClientHello.

The provider also emits `network.extension.lifecycle` events for filter stop
reasons and backpressure recovery. Guard Monitor and `guardd` should treat
these events as advisory state, not policy decisions.

## Heartbeat and Backpressure

When the manifest provides `paths.heartbeatPath`, the provider writes a compact
heartbeat JSON file at startup, shutdown, and at most once every five seconds
while flows are handled. The heartbeat includes policy load state, policy
sequence, stale/fallback status, event log path, event backpressure state, and
the number of dropped events since the last backpressure recovery. `guardd` and
the UI can use it to distinguish a running extension with a stale policy from a
stopped extension or missing app-group sync.

Event JSONL writes are best effort. Before appending a decision, the provider
checks `maxEventBacklogBytes`. If the event log is larger than that limit, it
allows policy decisions to continue, suppresses additional JSONL writes, marks
`eventBackpressure: true` in the heartbeat, and increments `droppedEventCount`.
Once the daemon drains or rotates the log below the limit, the provider emits a
single `network.extension.lifecycle` event with
`reason: "event-backpressure-recovered"` and the dropped count before resuming
normal decision events.

This backpressure behavior matches the manifest's current
`fallback.eventBackpressure: "allow-with-backpressure-event"` contract: flow
enforcement continues from the latest loaded policy, while monitor delivery is
degraded and visible through heartbeat state.

The extension should make only coarse flow decisions unless a future entitlement
and architecture change gives it a safe decrypting/proxy role. Deep HTTP or
TLS-aware allow/deny policy remains in the Guard proxy and `iron-proxy` layer,
where the user can explicitly configure trusted interception and CA scope.

Development requirements:

- Apple Developer signing with the Network Extension entitlement.
- A containing app that installs/enables the extension through System Settings.
- A daemon or app-group storage path shared with Guard Monitor for JSONL events.
- Clear UI labels for filter state, proxy state, and which layer made each
  decision.

Files:

- `GuardNetworkExtensionProvider.swift`: `NEFilterDataProvider` scaffold with
  JSON policy snapshot loading, coarse allow/drop decisions, and JSONL monitor
  event emission.
- `GuardNetworkExtension.entitlements.plist`: entitlement template. Replace
  `TEAMID.dev.guard` with the actual app group.
- `Info.plist`: extension plist template for an Xcode extension target.
