# Experimental Native macOS App Profiles

Native app profiles are experimental. They launch selected macOS apps with a
Guard policy instead of letting the app inherit broad local filesystem and
network access.

## Benefit

Conferencing and helper apps often need camera, microphone, network, app
support data, and local caches. Guard profiles make that access reviewable and
keep unrelated local files out of scope.

## Defaults

Guard currently ships experimental built-in profiles for:

- Zoom
- Microsoft Teams
- Webex

These profiles deny broad local filesystem access, reopen the app bundle and
known required support paths, and constrain network egress to profile-specific
vendor domains where practical.

## Usage

```sh
guard run zoom
guard run teams
guard run webex
guard install-apps
```

You can also invoke a vendor binary explicitly:

```sh
guard --profile zoom -- /Applications/zoom.us.app/Contents/MacOS/zoom.us
guard --profile teams -- "/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams"
guard --profile webex -- /Applications/Webex.app/Contents/MacOS/Webex
```

## What It Protects

Native profiles protect against:

- broad reads from user homes, mounted volumes, and unrelated app data.
- writes outside reviewed app-support and cache paths.
- unexpected domains outside the app profile.
- accidental use of a discovery profile after policy is locked.

## Global Defaults

App launchers are installed by:

```sh
guard install-apps
```

The current native monitor and app wrappers are experimental. They are useful
for local testing, but they are not yet signed, notarized, or installer-ready.

For stronger isolation, use a separate macOS user account or VM.
