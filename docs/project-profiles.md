# Project Profiles and Templates

Project profiles are the durable policy files that Guard applies to commands
run inside a repo.

## Benefit

A profile lets a project declare its expected filesystem, subprocess, and
network behavior once, then reuse that policy for developers, local CI-like
runs, and coding agents.

## Defaults

`guard init` creates `.guard/guard.json` using the `node-app` template:

```json
{
  "imports": ["node-app-defaults"]
}
```

Template imports live under `templates/imports`. The current Node defaults
enable the project filesystem sandbox, npm registry access, local dev-server
binding, install sandboxing, lifecycle-script scanning, and package lookup.

## Project Config

Use imports for shared defaults, then override only project-specific rules:

```json
{
  "imports": ["node-app-defaults"],
  "network": {
    "httpRules": [
      {
        "host": "api.openai.com",
        "methods": ["POST"],
        "paths": ["/v1/responses"]
      }
    ]
  },
  "filesystem": {
    "allowRead": ["${GUARD_PROJECT_DIR}/fixtures"],
    "allowWrite": ["${GUARD_PROJECT_DIR}/dist"]
  }
}
```

Common commands:

```sh
guard init
guard doctor
guard audit
guard list templates
guard profile doctor
guard diff-profile zoom teams
```

## What Profiles Protect

Profiles protect against policy drift. Instead of approving broad ad-hoc access
for each run, a repo can record the expected paths, hosts, HTTP paths, child
executables, and package-install behavior.

## Global Defaults

`guard setup` writes global local-machine settings such as:

- managed code root, for example `~/code`.
- shim install directory, for example `~/.local/bin`.
- whether package-manager shims are installed.

Those settings live outside the project and should not be used for durable
security policy. Put durable allow/deny rules in `.guard/guard.json`.

## Agent Guidance

For repos maintained with coding agents, run:

```sh
guard init-agent
```

This writes `AGENTS.md` guidance that tells agents to use narrow profile edits,
run `guard profile doctor`, and summarize policy changes before committing.
