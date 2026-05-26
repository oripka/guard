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
