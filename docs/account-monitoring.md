# Account session monitoring

Guard can monitor local developer-tool sign-in state without putting provider
logic or credentials in Guard itself. Account monitors live in the machine-local
user config at `~/.config/guard/config.json` under `accountMonitoring`.
Project `.guard/guard.json` profiles do not carry account commands, container
names, credential paths, or identities.

## Commands

```sh
guard account setup
guard account doctor
guard account list
guard account status codex-mac
guard account refresh cloudflare-wrangler
guard account preview aws-sso
guard account login aws-sso
```

`status` runs passive checks. `refresh` also runs monitors configured with
`status.cadence: "manual"`; use manual cadence for commands such as
`wrangler whoami` that contact a provider or refresh OAuth state.

`login` always runs in the caller's terminal with inherited terminal I/O. The
native Accounts window previews the target and redacted command, then opens a
private, self-deleting `.command` file that invokes only
`guard account login <id>`.

## Configuration contract

Each monitor supplies display metadata, a generic host or Docker target, a
status probe, zero or more local activity sources, and an optional login argv.
The core runner supports:

- `command`: bounded argv execution with exit-code, regex, and JSON Pointer
  result mapping.
- `jsonFiles`: read matching JSON credential metadata and extract only
  allowlisted snapshot fields.
- `latestMtime`: use the newest matching local file modification time.
- `guardEvents`: use the latest matching Guard event timestamp.

The normalized result is `AccountSessionSnapshot/v1`. It contains state,
identity when available, last-use time and source, expiry, check time,
staleness, and a reason code. It never contains raw stdout/stderr, environment
values, tokens, or unrestricted credential JSON.

Run `guard account setup` to add the default AWS SSO, host Codex, PacketSafari
worker Codex, Cloudflare Wrangler, and Tailscale monitors while preserving the
other user-config keys. All behavior remains editable in the resulting JSON;
provider names are display labels only.

## Security and accuracy

Guard executes monitor commands only from a regular user-owned config file that
is not group/world writable. Commands must be argv arrays. Explicit shell
interpreters are allowed but reported by `guard account doctor` for review.
Secret-bearing flags and configured stdin credential flows are rejected.
Credential-bearing login/target environment keys are rejected as well;
non-secret environment values are never shown in login previews.

Passive checks default to 60 seconds, run at most four at once, time out after
five seconds, and capture at most 64 KiB in memory. Normalized snapshots are
stored with mode `0600`. Events are emitted only when meaningful state changes.

“Last used” always names its local evidence source:

- AWS reports local CLI credential-cache activity, not CloudTrail activity.
- Codex reports local session-file activity.
- Wrangler reports Guard-observed Wrangler commands; unguarded commands may be
  absent.
- Tailscale reports local tailnet activity, not a specific Tailscale SSH
  check-mode authorization window.

Unknown or unavailable provider facts are shown as **Not observed** or
**Not exposed** rather than being inferred from the time Guard checked status.
