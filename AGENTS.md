# Agent Notes

## Product Direction

Build `guard` toward a clean Little Snitch-style security app for local
developer and native macOS workflows. The current CLI, sandbox profiles, app
launchers, network allowlists, and optional intercepting proxy should become
the foundation for a polished UI, reviewable rules, and clear notifications.

## Two-Mode Goal

Keep Guard cleanly split into two supported operating modes:

- Simple per-run mode: `guard`, `guard --ask-network`, and
  `guard --deep-egress --ask-network` must remain daemon-free, easy to reason
  about, and suitable for development commands, one-off shells, CI-like local
  runs, and quick repo exploration. This mode starts any needed local proxy for
  the current run only, stores temporary state under the run directory, and
  should keep working even when no Guard daemon, native UI, launch agent, or
  Network Extension is installed.
- Daemon/UI mode: `guardd`, Guard.app, native alerts, monitor windows, rule
  editors, persistent policy databases, and Network Extension integrations can
  provide the richer Little Snitch-style experience. This mode may manage
  shared policy state, persistent rules, event history, long-running proxy
  instances, and native notifications.

Do not make the simple per-run path depend on daemon/UI availability. The daemon
and UI should be additive: when available, the CLI may delegate richer policy
decisions to them; when unavailable, the CLI should retain the current local
fallback behavior.

Shared code should live behind clear boundaries so both modes use the same rule
language and policy semantics where practical:

- profile loading and template imports
- host/domain, method, path, and wildcard rule matching
- raw TCP destination rule normalization and launch-time host resolution
- iron-proxy config generation
- proxy environment generation for HTTP, SOCKS, SSH, Git, package managers,
  and helper scripts
- network decision/event schemas
- prompt decision protocol and result shapes
- audit/discovery summaries

Mode-specific code should stay separate:

- per-run prompt service and temporary decision cache
- daemon lifecycle and persistent rule store
- native menu bar app, alerts, rule editor, and monitor UI
- Network Extension/System Extension setup and adapters

## Target Architecture

The long-term design target is a unified macOS security app that combines
Guard's process/filesystem policy model with iron-proxy's deep HTTP policy and
Apple's modern Network Extension model. Prefer a System Extension plus
`NetworkExtension.framework` over any kernel extension approach.

Core components:

- `Guard.app`: native macOS UI with a menu bar monitor, live activity view,
  rules editor, profile/template editor, settings, and allow/deny/ask alerts.
- `guardd`: local policy daemon that owns persistent policy state, launches
  guarded runs, starts per-profile proxy instances, aggregates events, and
  exposes a local API to the UI and CLI.
- `guard` CLI: developer entrypoint that keeps current workflows working and
  delegates to `guardd` when available.
- `iron-proxy`: deep HTTP/HTTPS policy backend for domain, method, path,
  header, and request-level decisions when traffic is routed through the local
  proxy.
- Network Extension: app/process/destination-level visibility and coarse
  allow/deny enforcement for direct egress, bypass detection, and traffic that
  does not cooperate with proxy environment variables.
- sandbox layer: per-run filesystem containment, fake home/temp directories,
  read/write rules, and project/app profile enforcement.

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

## UI Direction

Build a native macOS app that feels as polished and direct as Little Snitch, but
do not copy Little Snitch private classes, nibs, icons, names, or assets. Use the
same Apple platform concepts and public frameworks: Swift, SwiftUI, AppKit,
NetworkExtension, MapKit, XPC, and system materials.

Current UI quality is not acceptable. The temporary prompt/dialog surfaces are
visually crude and should be treated as scaffolding only. The product goal is a
professional native macOS security UI with Little Snitch-level clarity, density,
and polish: careful hierarchy, strong spacing, crisp controls, native materials,
clear rule consequences, keyboard support, and no developer-tool-looking alert
boxes in the finished experience.

Connection prompts in particular must become polished, purpose-built native
panels rather than generic dialogs. They should make the actor, target, rule
scope, duration, and consequence immediately obvious:

- app/process identity with a trustworthy icon and command context
- destination host, port, protocol, method, and HTTP path where available
- selected rule scope preview before allowing, such as exact path, wildcard
  path, API group, host, or any connection
- clear lifetime controls: once, until quit, this session, always
- primary actions with correct destructive/default emphasis: Deny, Allow Once,
  Allow Rule, Edit Rule
- expandable details for certificate/TLS state, binary path, project/profile,
  matching rule, headers shown only when safe, and raw event JSON for debugging
- no oversized generic text, awkward button grouping, or vague labels
- no terminal-styled UI, debug log noise, or unpolished placeholder copy in
  the user-facing app

The native app should also include the same major functional surfaces expected
from a mature macOS network policy tool:

- Status menu popover:
  - menu bar status item with current mode, alert/silent state, and network
    inspection state
  - compact live traffic graph with upload/download rates and recent history
  - recent network activity grouped by app/process and command context, such
    as `Codex via gh`, browser, terminal, package manager, or guarded shell
  - prominent recently denied counter with quick navigation into filtered logs
  - quick actions for Manage Rules, Settings, pause/resume monitoring, toggle
    alert mode, and open the full monitor
  - visual density and polish comparable to top-tier macOS utilities: native
    materials, crisp SF Symbols-style iconography, rounded panels, keyboard
    navigation, and no placeholder/developer-looking controls
- Rules window:
  - sidebar sections for All Rules, Active, Deny, Recent Changes, Recently
    Used, Temporary, Unapproved, Rule Groups, and Blocklists
  - dense rules table grouped by process/app, with columns for process,
    identity/status badges, enabled state, allow/deny action, rule text,
    protocol/scope, group tags, approval state, and lock/managed state
  - support for rules such as any process, any macOS process, specific app,
    guarded command, domain, host, IP, CIDR, local network, method/path HTTP
    rule, incoming rule, outgoing rule, and blocklist entry
  - search, filtering, sorting, enable/disable toggles, temporary-rule
    indicators, unapproved blue-dot style review state, and group tags
  - rule detail/editor pane for scope, lifetime, profile, process identity,
    domain/host granularity, port/protocol, HTTP method/path wildcard, notes,
    approval, and audit history
- Settings window:
  - toolbar/tab layout with native icon tabs for General, Status Menu, Alert,
    Monitor, Apps/APS or Application Profiles, Security, DNS, Notifications,
    Update, Registration, and Advanced
  - Alert settings for detail level, preselected rule lifetime, active profile,
    domain/host granularity, port/protocol granularity, confirmation behavior,
    deny warning reset, keyboard confirmation, and automatic confirmation
    timeout rules
  - Advanced settings for marking new rules and blocklist entries as
    unapproved, approving rules automatically on selection, data-rate unit,
    additional local network ranges, packet/filter monitoring status, system
    extension install state, diagnostics, and reset/recovery actions
  - DNS, Security, and Network Extension panes that clearly explain active
    enforcement level, proxy CA trust, direct-egress monitoring, and degraded
    fallback behavior

Use native Swift components for these surfaces:

- `NSStatusItem`, `NSPopover`, and `NSMenu` for the status menu
- SwiftUI hosted in AppKit shells for popover contents and settings forms
- `NSPanel`/`NSWindow` for connection alerts with correct activation,
  keyboard, and focus behavior
- `NSToolbar` or SwiftUI toolbar integration for settings and rules windows
- `NSSplitViewController`, `NSTableView`, `NSOutlineView`, and SwiftUI detail
  inspectors for the rules and monitor windows
- `NSVisualEffectView`, system colors, SF Symbols-compatible iconography, and
  accessibility labels throughout

Do not ship a UI that merely exposes raw JSON logs, terminal text, generic
`display dialog` prompts, or placeholder web-style controls. These are allowed
only as temporary scaffolding while the native AppKit/SwiftUI surfaces are being
built.

Preferred UI stack:

- Use SwiftUI for new screens, state-driven view models, settings panes,
  profile/template editors, rule detail forms, and fast iteration.
- Bridge to AppKit where macOS-native behavior or performance matters:
  `NSStatusItem`, `NSMenu`, `NSPopover`, `NSPanel`, `NSTableView`,
  `NSOutlineView`, `NSSplitViewController`, `NSToolbar`, `NSVisualEffectView`,
  custom `NSView` drawing, and first-responder/key-equivalent handling.
- Use `NSHostingView`/`NSHostingController` and `NSViewRepresentable` to mix
  SwiftUI with AppKit controls cleanly.
- Avoid Electron, Qt, Flutter, web-shell UI, or heavy third-party UI frameworks.

Little Snitch-inspired component map:

- Menu bar/status item:
  - AppKit `NSStatusItem`/`NSStatusBar` host
  - SwiftUI or custom AppKit status item view for traffic meters, blocked
    indicators, and compact mode state
  - `NSMenu` and `NSPopover` for recent activity, denied items, quick settings,
    and links into the full app
- Rules window:
  - Sidebar using SwiftUI `List` or AppKit `NSOutlineView` when outline
    behavior is needed
  - Main rules table using `NSTableView`/`NSViewRepresentable` for dense,
    sortable, keyboard-friendly rules
  - Inspector/details pane with SwiftUI forms and AppKit popovers for advanced
    explanations
  - Toolbar using `NSToolbar` or SwiftUI toolbar bridged to AppKit semantics
- Settings window:
  - SwiftUI settings scenes/forms for modern maintainability
  - AppKit-backed controls where native macOS behavior is better, including
    segmented controls, sliders, pop-up buttons, tab views, and secure text
    fields
  - Dedicated panes for General, Network Extension, Proxy/CA, Alerts, Monitor,
    Profiles, Privacy, Updates, and Advanced
- Connection alert popup:
  - Custom `NSPanel`/`NSWindow` with strong keyboard handling and proper
    activation behavior
  - SwiftUI content hosted inside AppKit shell for message layout and actions
  - Clear buttons for Allow Once, Allow Path, Allow Domain, Deny, Details, and
    rule lifetime
  - `NSPopover` for consequences, matching rule explanations, and certificate
    or binary identity details
- Network Monitor:
  - Native window with `NSSplitViewController` layout
  - Connection list/table built on `NSTableView` for performance
  - SwiftUI inspector panels for selected connection, rules, identity, TLS
    status, and filesystem/process context
  - Custom SwiftUI/AppKit chart views for live traffic history
  - MapKit (`MKMapView`) for optional geographic destination view
  - `NSVisualEffectView` materials and system colors for a native macOS look
- Templates and profile editor:
  - SwiftUI-first, with structured forms, validation, diffs, import/export, and
    previews of effective filesystem/network/proxy policy

Design principles:

- Make the first screen useful, not a marketing page.
- Use system typography, spacing, materials, symbols, and color semantics.
- Keep information dense but readable; this is an operational security tool,
  not a decorative dashboard.
- Group noisy events and make decision reasons visible.
- Every allow/deny action should show the rule it will create before committing
  if the scope is broader than the exact event.
- Build view models and event schemas so UI tests can exercise behavior without
  needing the Network Extension entitlement.

Design goals:

- Keep the first production milestone focused on a native Guard UI over the
  existing sandbox and proxy policy engine.
- Include Network Extension support in the target design from the beginning.
  The first checked-in implementation can be a clean scaffold with explicit
  protocols, event models, and tests, even before entitlement-gated runtime
  activation is available.
- Treat the Network Extension as a first-class product component, not an
  afterthought. It should have a clear responsibility boundary, daemon
  contract, event schema, policy-decision API, and fallback behavior when the
  extension is not installed or not approved by macOS.
- Use the Network Extension for coarse app/process/destination policy and
  bypass detection; use iron-proxy for decrypted HTTP-level policy where proxy
  routing and certificate trust make that possible.
- Present all decisions through one rule model so users can understand whether
  a rule is filesystem, destination-level network, or HTTP-inspection based.
- Preserve portable project and app templates as a core Guard differentiator,
  not just a Little Snitch clone.
- Prefer clean, testable production code over temporary scripts. It is
  acceptable to introduce native Swift targets, XPC contracts, daemon modules,
  and typed event schemas when they make the architecture real and maintainable.

Known hard parts:

- Apple Network Extension entitlement approval.
- System Extension install, activation, disable, and recovery UX.
- Code signing, notarization, and update delivery.
- Correct XPC and privilege boundaries between UI, daemon, proxy, and extension.
- Avoiding accidental bypasses when apps ignore proxy settings.
- Certificate trust UX for HTTPS inspection and clear handling for certificate
  pinning.
- Privacy controls, redaction, and disclosure because decrypted HTTPS
  inspection is sensitive.

Phased implementation plan:

1. Guard Desktop MVP: native menu bar app showing current Guard runs, profiles,
   network logs, and allow/deny decisions from iron-proxy.
2. Policy Engine Daemon: move persistent policy state and event streaming into
   `guardd`, while keeping the CLI and current workflows working.
3. Little Snitch-style UI: rules table, live monitor, profile sidebar,
   settings, and ask popups.
4. Proxy Hardening: better HTTPS CA management, per-profile proxy instances,
   richer method/path/header rules, audit logs, and TLS failure explanations.
5. Network Extension: add app/process flow monitoring and coarse blocking;
   detect or block direct egress that bypasses iron-proxy.
6. Full Product Layer: installer, signed app wrappers, import/export,
   migration, template packs, diagnostics, and release/update flow.

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
