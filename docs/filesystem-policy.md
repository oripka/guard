# Filesystem Policy

Filesystem policy controls which local paths a guarded command can read and
write.

## Benefit

Unfamiliar code should not automatically read your whole home directory, cloud
credentials, SSH keys, package tokens, browser data, mounted volumes, or secret
files inside the repo. Guard makes those paths explicit and provides a fake
home/temp directory for each run.

## Defaults

Default project profiles:

- deny reads from `/Users`, `/Volumes`, `/Applications`, `/cores`, and `/home`.
- reopen `${GUARD_PROJECT_DIR}` and `${GUARD_RUN_DIR}`.
- allow writes to the project and the per-run directory.
- deny common secret writes such as `.env`, `*.pem`, `*.key`, and `secrets/`.
- add stronger read/write denies during package installs.

## Project Config

```json
{
  "filesystem": {
    "allowRead": [
      "${GUARD_PROJECT_DIR}",
      "${GUARD_RUN_DIR}"
    ],
    "allowWrite": [
      "${GUARD_PROJECT_DIR}/dist",
      "${GUARD_PROJECT_DIR}/node_modules",
      "${GUARD_RUN_DIR}"
    ],
    "denyReadAfterAllow": [
      "${GUARD_PROJECT_DIR}/.env",
      "${GUARD_PROJECT_DIR}/.ssh",
      "${GUARD_REAL_HOME}/.config/gh"
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

Run:

```sh
guard --allow-read ./fixtures --allow-write ./tmp pnpm test
guard profile add filesystem.allowRead ./fixtures
guard profile add filesystem.allowWrite ./tmp
guard profile add filesystem.denyRead ~/.ssh
```

## Dynamic Paths

Guard expands these placeholders for every run:

```text
${GUARD_PROJECT_DIR} -> project root
${GUARD_RUN_DIR}     -> per-run scratch directory
${GUARD_HOME_DIR}    -> fake HOME
${GUARD_TMP_DIR}     -> fake temp directory
${GUARD_REAL_HOME}   -> invoking user's real HOME
```

## What It Protects

Filesystem policy protects against:

- reads from home directories and mounted volumes.
- package installs reading `.env`, SSH keys, cloud credentials, or package
  tokens.
- writes to Git hooks, shell startup files, and project secret files.
- tools persisting state outside the project or Guard run directory.

## Global Defaults

Global defaults are runtime preferences such as state/config location:

```sh
GUARD_CONFIG_DIR=~/.config/guard
GUARD_STATE_DIR=~/Library/Application\ Support/guard
GUARD_HOME_BASE=/private/tmp/guard
```

Filesystem allow/deny rules should be project-local whenever possible.
