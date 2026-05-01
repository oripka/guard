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
