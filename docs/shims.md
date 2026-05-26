# PATH Shims

Guard shims are optional command links that sit earlier on `PATH` than the real
developer tools. They let ordinary commands such as `pnpm install` or
`node scripts/build.mjs` enter Guard automatically when you are inside a managed
code root.

## Benefit

Shims reduce the chance of accidentally running an unfamiliar repo outside
Guard. They are meant for everyday developer muscle memory: you can keep typing
`pnpm`, `npm`, `node`, `python`, or `pip`, and Guard decides whether to wrap the
command based on where you are and whether the project has a profile.

## Defaults

`guard setup` and `guard install` can create symlinks in the install links
directory, usually `~/.local/bin`.

Installed entrypoints:

- `guard`
- `guard-zoom`
- `guard-teams`
- `guard-webex`

Optional tool shims:

- `node`
- `pnpm`
- `npm`
- `python`
- `python3`
- `pip`
- `pip3`
- `uv`

Disabled shim tools:

- `npx`
- `corepack`
- `deno`

`npx` and `corepack` are disabled because they are easy hidden download and
execution paths. Use `pnpm exec`, add the package as a dev dependency, or run
the tool explicitly through `guard`.

## Setup

Interactive:

```sh
guard setup
```

Non-interactive:

```sh
guard setup --yes --code-root ~/code --bin-dir ~/.local/bin --shims
```

Install or refresh links:

```sh
guard install --code-root ~/code
guard install --code-root ~/code --no-shims
```

`code-root` is the parent directory where Guard should manage projects, for
example `~/code`, `~/src`, or `~/Projects`. Projects outside this root are left
alone by the shims unless you run `guard` directly.

## How It Works

Each shim is a symlink to `bin/guard`. The shell wrapper finds a real Node
binary outside Guard's shim directories and runs `lib/guard-cli.mjs`.

When invoked as a shim, Guard:

1. Identifies the tool name from `argv[0]`, such as `pnpm`.
2. Removes Guard shim directories from `PATH` to find the real tool.
3. If already inside a guarded run, executes the real tool directly to avoid
   recursion.
4. If outside the managed root, executes the real tool directly.
5. If inside the managed root but no `.guard/guard.json` exists, fails closed in
   non-interactive shells or asks before running unguarded in interactive
   shells.
6. If a project profile exists, runs the real tool through `guard`.

That means this:

```sh
cd ~/code/my-project
pnpm install
```

behaves like:

```sh
guard /real/path/to/pnpm install
```

## Project Config

A project only needs a normal `.guard/guard.json` profile:

```json
{
  "imports": ["node-app-defaults"]
}
```

For stricter child-process control, add the real tool paths that your scripts
need:

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

## Bypasses

Use explicit bypasses when you intentionally want the real tool:

```sh
guard off pnpm install
GUARD_SHIM_BYPASS=1 pnpm install
PNPM_GUARD_BYPASS=1 pnpm install
NODE_GUARD_BYPASS=1 node --version
```

When `guardd` is available, bypasses can be sent for approval before the
unprotected command starts. Set this to fail closed if approval is required:

```sh
GUARD_BYPASS_REQUIRE_APPROVAL=1 pnpm install
```

## Global Defaults

Guard stores setup choices in `~/.config/guard/config.json`:

- managed code root
- install links directory
- whether shims are included

Environment overrides:

```sh
GUARD_CODE_ROOT=~/code
GUARD_INSTALL_BIN_DIR=~/.local/bin
GUARD_SHIM_DIR=~/.local/bin
GUARD_SHIM_DIRS=~/.local/bin:/opt/guard/bin
GUARD_REAL_NODE=/opt/homebrew/bin/node
```

## What It Protects

Shims protect against:

- accidental unguarded package installs in managed repos.
- non-interactive scripts silently running tools without a Guard profile.
- recursive shim execution inside a guarded run.
- hidden use of `npx` or `corepack` as unreviewed download-and-execute paths.

Shims are not an enforcement boundary by themselves. They are a routing layer
into Guard's filesystem, subprocess, supply-chain, and network policy. A user
can still intentionally bypass them, so high-risk workflows should rely on the
profile policy and, later, daemon/UI or Network Extension enforcement.
