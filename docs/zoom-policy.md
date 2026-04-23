# Zoom Guard Policy

Use this built-in profile for launching the native macOS Zoom app with a
separate fake home directory and a fail-closed filesystem policy for user data.

```sh
guard --profile zoom -- /Applications/zoom.us.app/Contents/MacOS/zoom.us
```

Or use the convenience launcher:

```sh
bin/guard-zoom
```

If `bin/guard` is symlinked into `~/.local/bin`, `guard-zoom` can be symlinked
the same way:

```sh
ln -sf ~/code/guard/bin/guard-zoom ~/.local/bin/guard-zoom
```

## Policy Shape

The Zoom profile denies reads from user homes, mounted volumes, and
`/Applications` by default, then reopens only:

- `/Applications/zoom.us.app`
- the per-run guard directory
- the fake home and temp directories created by `guard`
- Zoom-specific application support, cache, log, preference, WebKit, and
  temporary paths

It writes only to the fake home/temp/run directories and explicit Zoom-specific
paths. The real home directory is still passed as `GUARD_REAL_HOME` for
diagnostics, but the sandboxed process gets `HOME` set to the fake home.

The network allowlist is limited to common Zoom-owned domains and is enforced
through the guard proxy. Add narrower exceptions only after a real launch log
shows Zoom needs them. Use `networkUnrestricted: true` only as a temporary
discovery setting.

See [critical-app-profiles.md](critical-app-profiles.md) for the shared
Teams/Webex/Zoom discovery and hardening workflow.

## Limits

This is an experimental app profile. Native conferencing apps integrate with
macOS services for camera, microphone, screen capture, accessibility, helpers,
and updates. Some of those flows may need additional narrowly scoped allowances
before the full app works.

For stronger isolation, use a separate macOS user account or a VM. This profile
is a local guardrail, not a replacement for OS account or VM isolation.
