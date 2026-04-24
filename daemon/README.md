# guardd prototype

This directory contains a bounded local daemon scaffold. It is intentionally
separate from the current per-run `guard` CLI path.

Run it with:

```sh
node daemon/guardd.mjs --event-log ~/Library/Application\ Support/guard/events.jsonl
```

Environment defaults:

- `GUARD_EVENT_LOG` overrides the JSONL event log path.
- `GUARD_STATE_DIR` changes the default state directory.
- `GUARDD_HOST`, `GUARDD_PORT`, `GUARDD_MAX_EVENTS`, and `GUARDD_POLL_MS`
  configure the prototype daemon.
- `GUARDD_POLICY_ROOT` points at a project root containing `.guard/*.json`
  project profiles. If unset, `GUARD_PROJECT_DIR` or the current working
  directory is used.
- `GUARDD_REPO_ROOT` points at the Guard repository root used for built-in
  `profiles/*.json` and `templates/*/guard.json`.
- `GUARDD_API_TOKEN` enables simple local API authentication. Send it as
  `Authorization: Bearer <token>` or `X-Guard-Token: <token>`.

When listening outside loopback, `guardd` requires `--api-token` or
`GUARDD_API_TOKEN`. The default listener remains `127.0.0.1`.

Read-only HTTP API:

- `GET /health` returns daemon status and tail state.
- `GET /events?limit=100&type=network.decision` returns recent parsed JSONL
  events, newest first.
- `GET /policy?profile=guard` returns the effective read-only profile config,
  with profile imports merged using the same JSON semantics as the CLI. The
  top-level `version`/`hash` fields refer to the selected profile file for
  write checks; `effectiveVersion`/`effectiveHash` refer to the merged config.
- `GET /profiles` lists project profiles from `.guard/*.json` and built-in
  profiles from `profiles/*.json`. Profile list entries include `version`,
  `hash`, and `shortHash` fields derived from stable profile JSON.
- `GET /profiles/:name` returns the raw selected project or built-in profile
  JSON. Project profiles win when names overlap. The response includes the same
  stable version/hash fields and an `ETag` header.
- `GET /templates` lists bundled project templates.
- `GET /templates/:name` returns raw bundled template JSON.
- `GET /templates/:name/preview?profile=guard` previews applying a bundled
  template to a project profile without writing. It returns the target path,
  whether the profile already exists, existing/template versions, and a compact
  effective summary based on merging the existing project config with the
  template JSON.

Authenticated write API:

- `POST /profiles/:name/rules` adds or removes project-local rules. Body:
  `{"action":"add","field":"network.allowedDomains","value":"api.example.com"}`
  or `{"action":"add","field":"network.httpRules","rule":{"host":"api.example.com","methods":["POST"],"paths":["/v1/*"]}}`.
  `action` may also be `disable` or `enable`. Disabled rules are removed from
  the active rule array and retained in `ruleMetadata` with `disabled: true`
  and the normalized rule value for review/editing.
- `POST /profiles/:name/tls` updates explicit project-local TLS inspection
  state. Body: `{"enabled":true}`.
- `POST /templates/:name/preview` is the body-based form of the preview
  endpoint. Body: `{"profile":"guard"}`. It does not mutate profile files and
  does not append a `policy.changed` audit event.
- `POST /templates/:name/apply` writes a bundled template to the project
  profile. Body: `{"profile":"guard","force":false}`.

Write endpoints require `GUARDD_API_TOKEN` / `--api-token` even on loopback.
Every successful mutation appends a `policy.changed` event to the Guard JSONL
event log.

Write endpoints accept an optional optimistic concurrency check using an
`If-Match` header or body field named `ifMatch`, `version`, or
`profileVersion`. Use the `version` value returned by `GET /profiles/:name` or
`GET /policy?profile=name`. If the current project profile version differs,
`guardd` returns `412` with `error: "version_mismatch"`. `If-Match: *` keeps the
old unconditional-write behavior.

This prototype stores only a bounded in-memory recent-event buffer and does not
own launch agents, native alerts, or Network Extension lifecycle yet.
