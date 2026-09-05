# Guard Agent Guidance

Build toward a native macOS security app with reviewable rules, clear decisions,
and polished UI. Keep simple per-run operation daemon-free: `guard`,
`guard --ask-network`, and `guard --deep-egress --ask-network` must work without
guardd, a native UI, a launch agent, or a Network Extension. Daemon/UI features
are additive, with shared policy semantics and explicit unavailable states.

## Security and product boundaries

- Keep domain proxy policy, deep HTTP policy, and raw TCP exceptions distinct.
  Cooperative proxy traffic must not imply permission for direct socket bypass.
- In the sandbox-exec backend, exact raw TCP exceptions are loopback-only.
  Host rules require explicit launch-time resolution; external SSH uses the
  SOCKS/ProxyCommand path. Do not add wildcard ports, raw DNS/ICMP, or CIDR-wide
  direct TCP without a product decision and matching audit/UI semantics.
- Keep secret disclosure, decrypted traffic, policy scope, and rule lifetime
  explicit and reviewable. Preserve narrow filesystem and network policy.
- Use Apple public frameworks and original assets. Do not copy private Little
  Snitch classes, nibs, icons, or assets. Prefer SwiftUI with AppKit where native
  behavior or performance requires it; avoid heavy web-shell UI frameworks.
- Do not present prototype or entitlement-gated capabilities as shipped.
  Network Extensions complement HTTP inspection and require explicit fallback
  behavior; they do not replace the functioning per-run path.

## Read only for the affected boundary

- Proxy and raw-egress changes: `docs/network-policy.md`.
- Daemon/shared architecture: `docs/guardd.md`.
- Native UI and design acceptance: `docs/ui.md`.
- Network Extension direction, future work, and validation categories:
  `docs/network-extension-roadmap.md`.
- Filesystem, subprocess, and secret handling: the matching policy document
  under `docs/`.

The design targets and test categories in those documents constrain relevant
work; they do not expand a requested change into a full product implementation
or a broad test run. Select validation proportional to the affected behavior.
