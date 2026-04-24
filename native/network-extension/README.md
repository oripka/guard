# Guard Network Extension Scaffold

Guard does not ship a runnable signed Network Extension bundle yet. The current
desktop app uses the local sandbox runner, Guard's proxy, and `iron-proxy` HTTP
policy prompts. This folder contains the source and entitlement scaffolding that
should be imported into a containing Xcode app target once Apple Developer
Network Extension capabilities are available.

The future macOS Network Extension should be a transparent user-approved
content filter that emits the same JSONL monitor events as the current runner:

- `backend: "network-extension"`
- `schemaVersion: 1`
- `type: "network.decision"`
- `host`, `port`, `protocol`, `direction`
- `appBundleIdentifier`, `processPath`, and `pid` when available
- `allowed`, `reason`, `ruleId`

The extension should make only coarse flow decisions. Deep HTTP or TLS-aware
policy remains in the Guard proxy and `iron-proxy` layer, where the user can
explicitly configure trusted interception.

Development requirements:

- Apple Developer signing with the Network Extension entitlement.
- A containing app that installs/enables the extension through System Settings.
- A daemon or app-group storage path shared with Guard Monitor for JSONL events.
- Clear UI labels for filter state, proxy state, and which layer made each
  decision.

Files:

- `GuardNetworkExtensionProvider.swift`: minimal `NEFilterDataProvider`
  skeleton. It currently allows flows and documents the future guardd policy
  call site.
- `GuardNetworkExtension.entitlements.plist`: entitlement template. Replace
  `TEAMID.dev.guard` with the actual app group.
- `Info.plist`: extension plist template for an Xcode extension target.
