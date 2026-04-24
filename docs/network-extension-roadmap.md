# Guard Desktop and Network Extension Roadmap

Guard's current enforcement model combines `sandbox-exec`, per-run filesystem
profiles, proxy environment injection, and the optional `iron-proxy` backend for
HTTP/HTTPS policy. This is the right base for a Little Snitch-style desktop
experience because it already has explicit launches, profiles, templates, and
deep request rules.

## Current Layer

- Guard launches selected commands and app profiles under a generated macOS
  sandbox profile.
- The built-in proxy backend filters by host/port.
- The `iron-proxy` backend can enforce HTTP method/path rules when traffic is
  routed through the proxy.
- Guard writes persistent monitor events to
  `~/Library/Application Support/guard/events.jsonl` by default.
- `guard monitor-log` and `Guard Monitor.app` read that event stream.
- `Guard Monitor.app` can turn selected network events into project-local
  domain allow/deny rules through `guard profile add`.

## Future Network Extension Layer

A macOS Network Extension would add system-level flow visibility and coarse
allow/deny controls. It should not replace `iron-proxy`; it should complement
it.

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
- `network.decision`

Future Network Extension events should use the same JSONL stream with a
different `backend`, for example `network-extension`.
