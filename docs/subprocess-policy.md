# Subprocess Policy

Subprocess policy controls which child executables a guarded command may start.

## Benefit

Many attacks start as a trusted command spawning a less trusted helper: a shell,
download tool, interpreter, Git, package manager, or OS automation tool.
Subprocess policy lets a profile move from "anything can execute" to a reviewed
allowlist.

## Defaults

Normal project profiles allow child execution unless configured otherwise. The
install hardening layer blocks common risky helpers during package-install
workflows. Use explicit deny mode when a project should only launch reviewed
tools.

## Project Config

```json
{
  "process": {
    "denyByDefault": true,
    "allowedExecutables": [
      "/usr/bin/env",
      "/bin/sh",
      "/opt/homebrew/bin/node",
      "/opt/homebrew/bin/pnpm",
      "${GUARD_PROJECT_DIR}/node_modules/.bin/*"
    ]
  }
}
```

Run:

```sh
guard --deny-subprocesses pnpm run build
guard --allow-exec ./scripts/codegen.sh pnpm run build
guard profile add process.allowedExecutables /opt/homebrew/bin/node
```

Include interpreters explicitly. A shell script needs `/bin/sh` or the shebang
interpreter. A Node project normally needs the real Node binary plus reviewed
tools under `node_modules/.bin`.

## What It Protects

Subprocess policy protects against:

- install scripts launching `curl`, `wget`, `nc`, `osascript`, or language
  interpreters as stagers.
- build tools invoking unexpected project-local executables.
- hidden package-manager or Git calls from an unfamiliar repo.
- accidental escape from a reviewed command into a broad shell.

## Global Defaults

Global shims are configured by `guard setup` or `guard install` and stored under
`~/.config/guard/config.json`. Common shims include `node`, `pnpm`, `npm`,
`python`, `python3`, `pip`, `pip3`, and `uv`.

`npx`, `corepack`, and `deno` are disabled by default as shims because they are
easy hidden download or execution paths. Run them explicitly through Guard when
needed:

```sh
guard npx vite --host 127.0.0.1
```
