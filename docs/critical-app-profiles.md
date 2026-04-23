# Critical App Profiles

Use the built-in app profiles for conferencing apps that need strong local
filesystem guardrails while still integrating with macOS services:

```sh
guard --profile teams -- "/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams"
guard --profile webex -- /Applications/Webex.app/Contents/MacOS/Webex
guard --profile zoom -- /Applications/zoom.us.app/Contents/MacOS/zoom.us
```

Convenience launchers are available when installed:

```sh
guard-teams
guard-webex
guard-zoom
```

## Baseline Shape

Every critical app profile starts from the same fail-closed baseline:

- `HOME` points at `${GUARD_HOME_DIR}` and `TMPDIR` points at `${GUARD_TMP_DIR}`.
- reads are denied from `/Users`, `/Volumes`, `/Applications`, `/home`, and
  `/cores`
- only the app bundle and explicit app-specific support/cache/log/preference
  paths are reopened
- writes are limited to the guard runtime, fake home/temp, and app-specific
  support/cache/log/preference paths
- local binding is disabled
- Docker sockets are not opened
- network egress is locked to a vendor domain allowlist through the guard proxy

The current built-in locked profiles are:

- `profiles/teams.json`
- `profiles/webex.json`
- `profiles/zoom.json`

## Discovery Workflow

Use discovery only to collect missing policy facts, not as the long-term
profile.

1. Start from the app profile with fake home/temp and the critical root denies.
2. Temporarily set `networkUnrestricted: true` only while collecting launch
   behavior, or use a temporary broad vendor allowlist.
3. Launch the app from Terminal and exercise the exact flows you care about:
   login, meeting join, camera, microphone, screen share, chat, paste, update
   check, and quit.
4. Capture denied reads, Mach lookups, Unix socket attempts, and network
   failures from the terminal output and system logs.
5. Add only narrowly scoped app bundle, app support/cache/log, Mach lookup, or
   socket rules that are necessary for those flows.
6. Remove discovery mode and keep `network.allowedDomains` as the final locked
   network policy.
7. Run `guard audit --profile <name>` and justify any remaining broad Mach
   lookup or Unix socket findings before committing the profile.
8. Run `guard profile doctor --profile <name>` before committing to catch
   missing metadata, missing deny roots, broad access, and unknown presets.

`guard discover` automates the temporary ask/log/report loop:

```sh
guard discover --profile teams -- "/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams"
guard network-log /private/tmp/guard/run-.../network-log.jsonl
```

Use `guard diff-profile zoom teams` to review how app profiles differ in terms
of app bundles, domain allowlists, Mach lookups, Unix sockets, and filesystem
carve-outs.

## Expected Hard Cases

Teams, Webex, and Zoom all use macOS integrations that may need iterative
policy tightening:

- camera, microphone, and screen-share TCC prompts
- WebKit/Electron helper processes
- updater helpers
- keychain and `securityd` access for login tokens
- pasteboard, WindowServer, and accessibility services
- vendor media, CDN, auth, and telemetry domains

Do not add Chrome or Slack profiles unless those apps are actually part of the
local workflow. Extra profiles create maintenance and audit surface without
protecting a real use case.
