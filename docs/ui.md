# Guard UI

Guard's UI work is experimental. The product direction is a polished native
macOS security app, but the current checked-in UI is still scaffolding for local
testing and iteration.

## Benefit

The UI makes Guard policy visible without reading JSON files or terminal logs.
It is intended to show current guarded activity, denied operations, pending
network decisions, rule state, TLS status, and settings in native macOS
surfaces.

## Current UI Surfaces

Guard has two native UI paths today:

- `GuardMacApp`: a SwiftPM menu bar monitor app with monitor, rules, and
  settings windows backed by local event and daemon APIs.
- `native/macos-launcher`: an AppKit launcher used by generated
  `Guard <App>.app` wrappers for app profiles such as Zoom, Teams, and Webex.

Both are experimental. They are not yet signed, notarized, installer-ready, or a
production replacement for the CLI.

## Menu Bar Monitor

Start the monitor:

```sh
guard ui
```

or install the monitor wrapper:

```sh
guard install-monitor
```

The monitor uses native AppKit/SwiftUI-style macOS surfaces, including:

- menu bar status item.
- status popover.
- live/recent activity monitor.
- rules window.
- settings window.
- daemon health and TLS status views.
- account-session status with last-used/expiry metadata and supervised login.
- event-log and daemon-backed refresh paths.

The monitor can start or connect to a local `guardd` for richer state and
mutating operations. It can also inspect the JSONL event log for recent activity
views.

## App Launchers

Install app launchers:

```sh
guard install-app zoom
guard install-app teams
guard install-app webex
guard install-apps
```

The generated `Guard <App>.app` wrapper:

1. reads `GuardAppConfig.json` from its bundle resources.
2. asks `guard app-summary --profile <name> --json` for effective policy.
3. shows a native preflight dialog with permissions and warnings.
4. launches `guard run <name>` after user confirmation.
5. writes app stdout/stderr to `~/Library/Logs/guard/<profile>.log`.

These launchers are useful for testing app profiles, but app profiles are still
experimental. See [Experimental native macOS app profiles](native-apps.md).

## Daemon Interaction

The UI uses [guardd](guardd.md) for stateful operations:

- event queries and indexed summaries.
- pending alert review and resolution.
- profile/rule listing and edits.
- TLS CA artifact generation, rotation, and diagnostics.
- security status.
- Network Extension sync scaffold state.

The CLI remains independent. If `guardd` or the UI is unavailable, ordinary
guarded runs still use the per-run sandbox and local proxy fallback.

## What It Shows

The intended UI model includes:

- current guarded processes and command context.
- filesystem and sandbox denials.
- proxied and denied network traffic.
- pending allow/deny decisions.
- profile rules and temporary decisions.
- secret-injection rules with real values redacted.
- TLS CA and inspection status.
- daemon health, token state, and diagnostics.

## What It Does Not Do Yet

The current UI does not yet provide:

- production signing or notarization.
- polished installer/update flow.
- production launchd management for `guardd`.
- Network Extension approval, activation, and recovery UX.
- final Little Snitch-style alert panel polish.
- complete accessibility and screenshot test coverage.

## Development

SwiftPM app:

```sh
cd native/GuardMacApp
swift build
swift test
swift run GuardMacApp
```

Launcher build:

```sh
xcrun swiftc -O -framework AppKit \
  native/macos-launcher/GuardAppLauncher.swift \
  -o native/macos-launcher/.build/GuardAppLauncher
```

Keep UI code native: Swift, SwiftUI, AppKit, `NSStatusItem`, `NSPopover`,
`NSPanel`, `NSTableView`, `NSVisualEffectView`, and system colors/materials.
Avoid web-shell UI for production Guard surfaces.

## Detailed design targets

These are design requirements, not claims of shipped capability.

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
