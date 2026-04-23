# Guard macOS Launcher

This directory contains the native AppKit launcher used by generated
`Guard <App>.app` wrappers.

The wrapper app:

- reads `GuardAppConfig.json` from its bundle resources
- asks `guard app-summary --profile <name> --json` for the effective policy
- shows a native macOS preflight dialog with permissions and warnings
- launches `guard run <name>` only after the user clicks Launch
- writes stdout/stderr to `~/Library/Logs/guard/<profile>.log`

Build manually:

```sh
xcrun swiftc -O -framework AppKit \
  native/macos-launcher/GuardAppLauncher.swift \
  -o native/macos-launcher/.build/GuardAppLauncher
```

Normal users should use:

```sh
guard install-app webex
guard install-app teams
guard install-app zoom
guard install-apps
```
