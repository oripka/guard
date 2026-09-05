# Guard Desktop and Network Extension Roadmap

Guard's current enforcement model combines `sandbox-exec`, per-run filesystem
profiles, proxy environment injection, and the default `iron-proxy` backend for
HTTP/HTTPS policy. The product focus is guarded-run developer and app workflows,
not system-wide interception of arbitrary unguarded apps.

## Current Layer

- Guard launches selected commands and app profiles under a generated macOS
  sandbox profile.
- The `iron-proxy` backend enforces HTTP method/path rules when traffic is
  routed through Guard's proxy.
- Guard writes persistent monitor events to
  `~/Library/Application Support/guard/events.jsonl` by default.
- On macOS, guarded runs start one filtered unified-log stream scoped to the
  run's sandbox `with message` tag. This best-effort bridge records
  `sandbox.denial` events for denied file, subprocess, and other sandbox
  operations without polling the system log.
- `guard monitor-log` and `Guard Monitor.app` read that event stream.
- `Guard Monitor.app` can turn selected network events into project-local
  domain allow/deny rules through `guard profile add`.

## Future Network Extension Layer

A macOS Network Extension would add system-level flow visibility and coarse
allow/deny controls. It should not replace `iron-proxy`; it should complement
it. This is entitlement-gated future work, not a current runtime path.

Recommended split:

- Network Extension: app/process identity, direction, remote endpoint, protocol,
  direct-egress detection, coarse blocking.
- `iron-proxy`: decrypted HTTP policy such as host, method, path, headers, and
  request/response limits.
- Guard daemon: policy database, XPC/API boundary, extension/proxy event merge,
  profile/template management.
- Guard UI: monitor, rules, settings, prompts, and import/export.

## Signing Reality

Network Extensions require Apple capabilities, code signing, user approval in
System Settings, and different distribution work from the current ad-hoc signed
launcher apps. Development should start with a separate Xcode target once an
Apple Developer team and entitlements are available.

## Event Contract

The desktop UI should consume a single append-only event stream regardless of
source. Events include `schemaVersion: 1` so future daemon and Network Extension
adapters can evolve without breaking the monitor. Current event types:

- `sandbox.profile_written`
- `proxy.started`
- `process.started`
- `process.exited`
- `sandbox.denial`
- `network.decision`

Future Network Extension events should use the same JSONL stream with a
different `backend`, for example `network-extension`.

## Candidate work and validation scope

The following describes potential work and validation categories, not automatic
permission to implement every item or run every suite.

## Test Suite Plan

Build the product with tests at each boundary instead of relying only on manual
macOS UI checks.

- Policy engine tests:
  - rule matching for filesystem, destination network, and HTTP-inspection
    scopes
  - precedence, temporary rules, profile inheritance, and deny-overrides-allow
    behavior
  - portable profile/template import, validation, and migration
- Sandbox tests:
  - generated `sandbox-exec` profile snapshots
  - allowed and denied read/write probes against temp directories
  - fake home/temp isolation and secret-file denial
  - regression tests for app profiles and project templates
- iron-proxy tests:
  - host/domain wildcard matching
  - method/path/header decisions
  - TLS CA setup states and certificate-pinning failure classification
  - JSONL/network event emission and byte counters where available
- Daemon and API tests:
  - `guardd` policy persistence
  - event ingestion from proxy, CLI, sandbox, and Network Extension adapters
  - XPC/local API authorization and schema compatibility
  - lifecycle tests for starting/stopping per-profile proxy instances
- Network Extension tests:
  - unit tests for flow-to-event normalization and policy requests
  - mocked `NEFilterFlow`/adapter tests so core logic runs without entitlements
  - integration tests gated behind signing/entitlement availability
  - bypass-detection scenarios for direct egress, proxy egress, denied flows,
    and extension-disabled fallback
- Native UI tests:
  - view-model tests for rules, monitor rows, settings, and alert decisions
  - snapshot or screenshot tests for key AppKit/SwiftUI screens
  - accessibility checks for alerts and rule tables
  - end-to-end smoke tests that launch a guarded process, trigger an unknown
    network request, approve/deny it, and verify the resulting rule/event
- Packaging tests:
  - signed/notarized build verification when credentials are available
  - installer or app-wrapper smoke tests
  - upgrade/migration tests for policy databases and templates

## Todo Ideas

- Design a native-feeling macOS UI around guard functionality:
  - show active guarded processes and app profiles
  - show effective filesystem and network permissions before launch
  - provide simple allow, deny, and ask flows for network events
  - make rules easy to inspect, edit, and disable

- Build a Little Snitch-like network monitor:
  - live per-process connection view
  - domain, IP, port, protocol, method, and path visibility where available
  - temporary and persistent allow/deny rules
  - notifications for new or suspicious destinations

- Expand the intercepting proxy workflow:
  - keep sandboxed apps constrained to the local proxy
  - support HTTP method and path rules
  - make rule prompts understandable for non-expert users
  - expose network logs in the UI with filtering and search

- Add certificate pinning and TLS inspection detection:
  - detect when a process bypasses, rejects, or cannot use the guard CA
  - notify the user when TLS inspection is unavailable for a destination
  - distinguish pinned TLS, unsupported protocols, direct socket bypasses, and
    ordinary proxy or certificate configuration failures
  - provide recommended actions such as allow without inspection, deny, or run
    with stricter network isolation

- Add binary signing and identity detection:
  - inspect code signatures for launched binaries and app bundles
  - show developer ID, team ID, signing status, notarization status where
    available, bundle ID, and executable path
  - warn on unsigned, ad-hoc signed, modified, or unexpectedly replaced
    binaries
  - bind rules to a stable binary identity instead of only command names or
    paths

- Improve rule engine capabilities:
  - support per-project, per-app, per-binary, and global rule scopes
  - support temporary rules with expiration
  - support rule precedence, audit trails, and dry-run explanations
  - make rules portable as checked-in project policy when appropriate

- Improve notifications and review flows:
  - notify on first-seen binaries, new destinations, denied writes, blocked
    secret access, TLS inspection failures, and policy drift
  - provide a compact event history with clear reasons for each decision
  - make noisy events groupable so routine developer workflows stay usable

- Build toward complete Little Snitch-style capabilities plus guard-specific
  controls:
  - network visibility and approval
  - local filesystem containment
  - app and project profiles
  - intercepting proxy rules
  - TLS inspection status
  - binary identity and signing awareness
  - clean UI for everyday use
