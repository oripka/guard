# Secret Injection

Secret injection lets a guarded workload use an API credential without putting
the real secret inside the sandboxed process environment, command line, source
tree, or logs.

## Benefit

Developer commands often need credentials such as API keys, package tokens, or
deployment tokens. Passing the real value directly to an unfamiliar repo makes
it easy for code to print it, read it from `process.env`, write it to disk, or
reuse it for a different destination.

Guard's current secret injection model keeps the real value on the proxy side.
The workload sees only a harmless proxy token. When a matching request passes
through `iron-proxy`, Guard swaps that proxy token for the real secret only for
the configured host, method, path, and header.

For environment-backed secrets, Guard also strips the configured source
variables from the sandboxed child process environment. The runner and proxy can
read the real value before launch, but the workload does not inherit that env
var by default.

## Defaults

Secret injection is off by default. Enable it per project in
`.guard/guard.json` under `network.secretInjection`.

It requires the `iron-proxy` network backend because the substitution happens at
the HTTP proxy boundary.

```json
{
  "network": {
    "backend": "iron-proxy",
    "tlsInspection": {
      "enabled": true,
      "mode": "ephemeral-run-ca"
    }
  }
}
```

For plain HTTP targets, TLS inspection is not relevant. For HTTPS targets,
decrypted HTTP inspection must be active for Guard to see and rewrite headers.

## Project Config

Example: let app code use a fake OpenAI token while Guard injects the real
`OPENAI_API_KEY` only for `POST /v1/responses`.

```json
{
  "network": {
    "backend": "iron-proxy",
    "httpRules": [
      {
        "host": "api.openai.com",
        "methods": ["POST"],
        "paths": ["/v1/responses"]
      }
    ],
    "secretInjection": [
      {
        "name": "OPENAI_API_KEY",
        "source": {
          "type": "env",
          "var": "OPENAI_API_KEY"
        },
        "proxyValue": "guard-proxy-openai-token",
        "matchHeaders": ["Authorization"],
        "require": true,
        "rules": [
          {
            "host": "api.openai.com",
            "methods": ["POST"],
            "paths": ["/v1/responses"]
          }
        ]
      }
    ]
  }
}
```

The guarded process should use the proxy token:

```sh
OPENAI_API_KEY=sk-real-value-from-your-shell \
  guard --ask-network node scripts/call-openai.mjs
```

Inside the workload, send:

```text
Authorization: Bearer guard-proxy-openai-token
```

The upstream server receives:

```text
Authorization: Bearer sk-real-value-from-your-shell
```

The guarded process never receives `sk-real-value-from-your-shell` from Guard.
It can still read the committed project profile and see the proxy token, so the
security boundary is the scoped proxy rewrite, `require: true`, and the narrow
HTTP rules, not secrecy of the placeholder token.

## Fields

`name`: human-readable label shown in summaries and UI surfaces.

`source`: where the proxy reads the real secret. The current practical source
is environment variables:

```json
{ "type": "env", "var": "OPENAI_API_KEY" }
```

The generated proxy config also carries fields for future secret backends:
`secret_id`, `region`, `json_key`, and `ttl`.

`proxyValue`: placeholder value the workload is allowed to know.

`matchHeaders`: request headers to inspect and rewrite. Defaults to
`["Authorization"]`.

`matchBody`: whether body matching is enabled. Keep this off unless there is a
specific reviewed need.

`require`: when `true`, matching requests must contain the proxy value.
Requests with a different value are rejected instead of being forwarded.

`rules`: HTTP routes where substitution is allowed. Use the narrowest host,
method, and path that works.

## What It Protects

Secret injection protects against:

- app code reading the real API key from the environment.
- accidental logging of real request credentials by the workload.
- broad use of a token on unreviewed hosts or paths.
- bypass attempts where code sends its own credential value instead of the
  configured proxy token, when `require` is true.

It does not protect against a malicious dependency that can intentionally read
the project profile, find the proxy token, and send requests to an allowed route.
Pair secret injection with narrow `network.httpRules`, `require: true`,
filesystem secret denies, subprocess policy, and package-install hardening.

## Global Defaults

Real secret values should normally come from your shell, password manager
wrapper, or future daemon/Keychain integration. Do not commit real values to
`.guard/guard.json`.

Useful local environment pattern:

```sh
export OPENAI_API_KEY="$(security find-generic-password -w -s openai-api-key)"
guard --ask-network node scripts/call-openai.mjs
```

Project config should commit only the proxy token and scoped rules, not the real
credential.

## Testing

Use a local endpoint to confirm the rewrite:

```sh
guard --profile network-iron-secret-injection \
  curl --noproxy '' \
  -H 'Authorization: Bearer guard-proxy-openai-token' \
  http://localhost:8976/secret
```

Guard's test suite covers:

- proxy token replacement on matching routes.
- rejection when `require` is true and the proxy token is missing.
- nonmatching paths leaving the proxy token unchanged.
