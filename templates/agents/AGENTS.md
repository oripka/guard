# Guard Profile Authoring Notes

This repository uses Guard for local filesystem and network containment. When
you change project dependencies, development servers, deployment tools, or
external API usage, keep `.guard/guard.json` reviewable and narrow.

## Agent Workflow

1. Inspect the project before editing policy:
   - package manifests and lockfiles
   - scripts and dev-server ports
   - deployment/config files
   - documented external APIs
   - test fixtures, generated folders, cache folders, and local data paths
2. Start from a reusable template:
   - `guard init` for a Node/default project
   - `guard init cloudflare-wrangler` for Wrangler-based projects
3. Prefer small profile edits through the CLI:
   - `guard profile add network.allowedDomains example.com`
   - `guard profile add-http-rule --host api.example.com --method POST --path /v1/*`
   - `guard profile add filesystem.allowRead ./fixtures`
   - `guard profile add filesystem.allowWrite ./tmp`
4. Validate and explain the result:
   - `guard profile doctor`
   - `guard audit`
   - `guard doctor --json`
   - run the intended command through `guard`

## Policy Rules

- Keep the default posture narrow: project files plus Guard's per-run directory.
- Do not use `networkUnrestricted: true` unless the user explicitly accepts the
  broad network consequence for a trusted command.
- Use `network.allowedDomains` for compatibility domain allows.
- Use `network.httpRules` for method/path scoped HTTP policy when traffic goes
  through `iron-proxy`.
- Use `network.allowedRawTcp` only for explicit loopback `ip:port` rules, or
  `host: localhost` with `resolveAtLaunch: true`.
- Do not add wildcard ports, CIDR-wide direct TCP, raw DNS, or raw ICMP rules.
- Prefer the Guard SOCKS/SSH proxy path for Git or SSH workflows instead of raw
  external TCP exceptions.
- Keep secret files denied by default: `.env`, `.env.*`, `*.pem`, `*.key`, and
  `secrets/`.
- Add comments in your final response explaining why each allow rule is needed.

## Suggested Prompt

Ask the coding agent:

> Review this repo and create or update `.guard/guard.json` for the normal
> development workflow. Keep filesystem and network rules narrow, prefer HTTP
> method/path rules for known APIs, avoid `networkUnrestricted`, run
> `guard profile doctor` and `guard audit`, then summarize each rule you added.
