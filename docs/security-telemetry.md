# Security telemetry groundwork

Guard records deterministic security facts. It does not use an LLM for
enforcement, authorization, policy mutation, or claims that a machine is
secure or infected.

## Additive event identity

Event schema version 1 remains supported. New producers can add telemetry
version 1 fields without changing existing consumers:

- `eventId`: unique evidence identifier
- `runId`: stable identifier for one guarded run
- `sequence`: monotonic event order within the run
- `parentEventId`: causal parent, normally the guarded `process.started` event
- `monotonicNs`: producer-local monotonic observation time
- `policySnapshotId`: digest of the effective policy

Process events can additionally provide `pid`, `parentPid`, `responsiblePid`,
`processArguments`, and `commandFingerprint`. Arguments are structured,
bounded, and redact common credential-shaped values. They are still
attacker-controlled data and must never be treated as instructions.

## Evidence windows

`buildEvidenceWindows` groups bounded event sets by run and time window. The
result contains event IDs, event-type counts, process IDs, destinations,
sensitivity classes, byte totals, denial counts, and explicit telemetry
limitations. It is suitable for deterministic detectors, UI summaries, or a
future read-only analyst.

Raw event storage remains the source of truth. Evidence windows are derived
views and do not make allow/deny decisions.

When daemon/UI mode is available,
`GET /security/evidence-windows?windowMs=300000&limit=250&privacy=redacted`
returns this bounded view. Legacy events without evidence identifiers are
reported as skipped rather than receiving invented identities.

## Privacy projection

`projectSecurityEvent` produces a strict allowlisted representation:

- `local`: retains local identifiers.
- `redacted`: removes full process paths and uses project/resource identities
  rather than unrestricted log text.
- `pseudonymous`: replaces projects, destinations, and resources with stable
  keyed pseudonyms.

No mode includes file contents, HTTP bodies, headers, environment values, or
unrestricted command output.

## Findings and policy proposals

The versioned schemas in `schemas/` define two future-facing contracts:

- A security finding must cite at least one known `eventId`.
- A policy proposal is additive, narrow, evidence-backed, and always marked
  `requiresHumanApproval: true`.

The deterministic proposal validator rejects unknown fields, mutation types,
and broad values such as `*`, `/`, or an all-network CIDR. Applying a proposal
is deliberately not implemented here.

Authenticated daemon clients can validate these contracts through
`POST /security/findings/validate` and
`POST /security/proposals/validate`. These endpoints validate evidence against
the daemon's retained event IDs; they do not persist a finding, change a
profile, or apply a rule.

## Coverage boundaries

This groundwork improves telemetry from Guard-managed runs. It does not provide
whole-machine process/file visibility, direct-egress coverage, successful file
read observation, or persistence monitoring. Those require separately approved
Endpoint Security and Network Extension components. The daemon-free Guard path
does not depend on either extension.
