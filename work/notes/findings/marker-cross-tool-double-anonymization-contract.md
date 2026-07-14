---
title: The double-anonymization marker contract sibling tools read at /etc/anonctl/<account>.json
slug: marker-cross-tool-double-anonymization-contract
source: 'derived from reading marker/marker.go @ 363be69 (weakest provenance: assumes our code is the contract; upgrade to a captured cross-tool read or a maintainer confirmation before trusting against anon-pi/netcage)'
---

## What this describes

The on-disk **coordination contract** that `anoncore` PRODUCES and that EXTERNAL sibling tools (`anon-pi`, `netcage`) CONSUME to implement the Tor-over-Tor guard. This is external/domain ground-truth (the cross-tool wire shape a different codebase parses), not a description of anoncore's own module layout, so it lives here rather than in `CONTEXT.md`/`docs/`.

## The contract

- **Path:** `/etc/anonctl/<account>.json`, one file per forced account. The base directory is `marker.DefaultBaseDir` (`/etc/anonctl`), overridable per-`Store` via `BaseDir` (anonbox and tests point it elsewhere; the `/etc/anonctl` value is anonctl's published default).
- **Discovery is the file, not the name.** A consumer reads the JSON directly with NO anonctl binary in the loop. The `anon` / `anon-<name>` login-name prefix is a HINT only, never authoritative.
- **Presence semantics.** A present, parseable marker = "this account is (claimed to be) already kernel-anonymized" → the consumer SKIPS re-forcing a proxy. A missing file is a clean "not forced" negative (`ErrNotFound`), not an error. A present-but-corrupt file IS an error (not silently treated as absent).
- **It is a CLAIM, not a live proof.** anonctl writes the marker only AFTER its own `verify` passes (`WriteVerified` refuses when verify did not pass), and removes it on teardown. A consumer that needs certainty runs its own leak check; the marker just lets it skip redundant forcing.

## Wire shape (schemaVersion 1)

JSON object, indented, fields:

- `schemaVersion` (int) — contract version; starts at 1, evolves ADDITIVELY (new optional fields only); a breaking change bumps it. A consumer guards on it FIRST.
- `account` (string) — the forced Unix login (`anon` / `anon-<name>`).
- `uid` (string) — the forced account's numeric UID as a string.
- `endpointClass` (string) — the endpoint share-class (`tor-shared` / `socks-peruser`): the ONE piece of endpoint detail exposed.
- `createdAt` (string) — RFC3339 UTC, when verify passed and the claim was made.
- `anonctlVersion` (string) — the anonctl build that wrote the claim.

## Load-bearing invariants a consumer relies on

- **Credential-free by construction.** The file is world-readable (dir `0755`, file `0644`), so it carries NO endpoint URL or credentials. The endpoint URL/creds live in the account's own non-world-readable config, never here. A consumer must not expect a secret in the marker.
- **Version gating is strict-forward.** Parsing refuses a `schemaVersion` HIGHER than the reader understands (loud refusal, not a partial read), and refuses `schemaVersion == 0` (not an anonctl marker). A consumer pinned to version N keeps working as producers add optional fields at version N.
- **Account-name path safety.** The producer validates the account name (no path separators / `..`) before forming `<BaseDir>/<account>.json`, so a crafted name cannot escape the base dir.

## Why this is a finding, and how to strengthen it

The `source:` is code-derived (reading `marker/marker.go`), which is the WEAKEST provenance: it assumes anoncore's code IS the real cross-tool contract. It is worth upgrading to a captured trace of `anon-pi`/`netcage` actually reading a marker, or a maintainer confirmation of the consumed field set, so a future "the consumer expected a different shape" can be traced and revised. The producer side is additionally pinned by `marker/marker_test.go`.
