# Node App Guard Policy

Use this profile shape for local Node, Nuxt, Vite, Slidev, Wrangler, and similar
developer workflows.

This policy is intentionally fail-closed for user data and mounted volumes:

- all reads under `/Users` are denied by default
- all reads under `/Volumes` are denied by default
- common nonessential roots such as `/Applications`, `/cores`, and `/home` are
  denied by default
- only paths listed in `allowRead` are reopened

Do not create project configs with empty `denyRead` or broad home/volume reads.

```json
{
  "allowPty": true,
  "network": {
    "ask": false,
    "allowedDomains": [],
    "deniedDomains": [],
    "allowLocalBinding": true,
    "allowLoopbackConnections": false,
    "allowLoopbackHighPorts": false,
    "allowLoopbackPorts": [
      3000,
      3001,
      4983
    ],
    "allowUnixSockets": [
      "${GUARD_RUN_DIR}"
    ],
    "allowMachLookup": [
      "com.apple.FSEvents",
      "com.apple.fseventsd",
      "com.apple.FileCoordination"
    ]
  },
  "filesystem": {
    "denyRead": [
      "/Users",
      "/Volumes",
      "/Applications",
      "/cores",
      "/home"
    ],
    "allowRead": [
      "${GUARD_PROJECT_DIR}",
      "${GUARD_RUN_DIR}"
    ],
    "allowWrite": [
      "${GUARD_PROJECT_DIR}",
      "${GUARD_RUN_DIR}"
    ],
    "denyWrite": [
      ".env",
      ".env.*",
      "secrets/",
      "*.key",
      "*.pem"
    ]
  }
}
```

## Why These Defaults

- `denyRead` blocks all user home directories, mounted external/network/vault
  volumes, and common nonessential roots by default. This is the core
  fail-closed rule.
- `allowRead` re-opens only the project root and the per-run directory that
  `guard` creates.
- `allowWrite` allows project output plus the controlled per-run guard
  directory.
- `denyWrite` protects common secret file names even inside an otherwise writable
  project.
- `allowLocalBinding` lets dev servers bind loopback localhost ports.
- `allowLoopbackPorts` lets worker/dev-server helpers connect back to exact
  localhost ports without granting external raw TCP egress.
- `allowLoopbackHighPorts` expands to the macOS ephemeral port range
  `49152-65535` for tools that choose random local callback ports. This is much
  narrower than all localhost ports, but larger and slower to compile than exact
  ports.
- `allowLoopbackConnections` allows all localhost TCP ports and should stay an
  escape hatch for tools that cannot be pinned or covered by high ports.
- `allowPty` lets interactive dev CLIs use terminal raw mode for shortcuts.
- `allowMachLookup` allows macOS file watching for Vite/Nuxt/Slidev.
- `guard` also allows the narrow sysctl reads that Node's macOS FSEvents
  integration needs, such as CPU/page-size/OS-variant lookups. Projects do not
  need to add these in their own profile.
- `allowUnixSockets` is limited to the same per-run guard directory so
  Nitro/Miniflare-style worker sockets can work without opening arbitrary Unix
  socket access.

## Guard Placeholders

`guard` resolves these placeholders before generating the native sandbox
profile:

- `${GUARD_PROJECT_DIR}`: directory containing the matched `.guard/` folder
- `${GUARD_CWD}`: directory where `guard` was invoked
- `${GUARD_RUN_DIR}`: per-config/per-working-directory runtime root
- `${GUARD_HOME_DIR}`: fake home directory inside the runtime root
- `${GUARD_TMP_DIR}`: temp directory inside the runtime root

## When A Project Needs More

Add the narrowest explicit path. Examples:

```json
"allowRead": ["~/code/my-app", "~/code/shared-package"]
```

```json
"network": {
  "allowedDomains": ["api.cloudflare.com", "*.supabase.co"]
}
```

For exploratory runs, prompt on first access to an unknown proxied host:

```sh
guard --ask-network pnpm run dev
guard --ask-network bash
```

Or enable it in the profile:

```json
"network": {
  "ask": true,
  "allowedDomains": [],
  "deniedDomains": []
}
```

Interactive shells use a macOS dialog for network prompts to avoid terminal job
control conflicts. Use `GUARD_ASK_NETWORK_UI=tty` to force terminal prompts or
`GUARD_ASK_NETWORK_UI=dialog` to force dialog prompts.

Prefer `${GUARD_PROJECT_DIR}` over a hardcoded local path so private repo
configs still work after a fresh checkout in a different location. Do not relax
`denyRead` unless the project has a clear reason to inspect the whole home
directory or all mounted volumes.
