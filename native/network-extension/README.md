# Future Network Extension Notes

Guard does not currently ship a runnable Network Extension. This directory is
kept only as a planning note for a future entitlement-backed system-wide network
mode.

Current Guard networking is intentionally scoped to guarded runs:

- `guard <command>` launches a process under the macOS sandbox.
- Guard injects HTTP/SOCKS proxy environment variables for the child process.
- The `iron-proxy` backend provides deep HTTP/TLS policy for cooperative
  clients, including host, method, path, and header matching.
- Unknown guarded-run requests can flow through `guardd` pending alerts and the
  native UI.

A future Network Extension would add Little Snitch-style visibility for apps
that were not launched through Guard. That requires Apple-approved Network
Extension entitlements, a containing signed app, System Extension activation,
and user/admin approval. Do not treat this directory as production code or as a
current enforcement path.

The future extension should be additive only: simple per-run Guard mode must
remain daemon-free and usable without a Network Extension.
