# anoncore

The shared, substrate-AGNOSTIC account/seed/marker/elevation core for the `anon*` family: `anonctl` today, and the planned `anonbox` and `anonseed`.

`anoncore` is a **library, not a binary**. It has no `main`, ships no command, and is imported by the tools that do. It holds the security-critical logic that is identical whether the egress substrate is anonctl's per-UID nftables forcing or anonbox's netcage network namespace: account provisioning (with NO sudo/wheel grant), the `seed-home` hardening (setuid-bit strip, symlink refusal, mode-700 home write), the world-readable credential-free marker contract, endpoint parsing/classification, the sudo-rights probe, and the tiny terminal UI helpers. It is shared (not copied) so this hardening cannot silently DRIFT between the tools that depend on it.

## What is in here

- **`account`** - the substrate-agnostic account-NAME vocabulary (`anon` default, `ResolveAccount`, `ShimAccount`, `IsAnonLogin`). The small shared language provisioning needs; each tool's own argv parser builds on it.
- **`provision`** - the account + dedicated-shim-UID lifecycle behind add/rm/list/status, all system mutation behind an injected `Runner` seam so it is unit-testable against a fake with NO real `useradd`.
- **`seedhome`** - the credential-shedding home seeder: strips setuid/setgid/sticky bits on copy, refuses symlinks, writes mode-700. Load-bearing for the "an anonymized home must not carry a uid-transition escape" guarantee.
- **`marker`** - the double-anonymization coordination contract: the versioned, credential-free JSON a sibling tool reads to detect "this account is already kernel-anonymized" and skip re-forcing a proxy.
- **`accountconfig`** - the per-account at-rest operational record (endpoint host:port + share-class, shim ports, UIDs) a tool re-applies forcing from.
- **`endpoint`** - socks5h endpoint parsing, share-class classification, and the credential-free-at-rest guard.
- **`sudoprobe`** - classifies `sudo -l -U <account>` output to assert an account has NO sudo rights (the hardened, expected state).
- **`ui`** - the tiny per-stream terminal color/styling layer (TTY + `NO_COLOR`/`FORCE_COLOR` aware), so the `--json` path stays byte-plain.

## What is NOT in here

The per-tool egress substrate glue stays in each tool's own repo. For anonctl that is the per-UID kernel forcing: `nftables`, `forcing`, `shim`, `lanexempt`, `systemd` (and the anonctl-config-specific `defaults`). anonbox will supply its own substrate (netcage argv); anonseed needs none. `verify` also stays per-tool for now: anonctl's verify asserts the nftables forcing and shim closures, which are substrate-specific; only its account-layer assertions might be shared later (see the founding ADR).

The precise, hard-to-reverse boundary is pinned in [`docs/adr/0001-module-boundary-shared-core-vs-per-tool-substrate.md`](docs/adr/0001-module-boundary-shared-core-vs-per-tool-substrate.md).

## Test discipline

Every package carries its unit tests, which run WITHOUT root against a fake `Runner` (`go test ./...`). The real `useradd`/`setpriv` behaviour lives behind the `integration` build tag and needs root (`go test -tags integration ./...`); those bodies SKIP (not fail) when not root, so an ordinary `go test ./...` is fully hermetic and touches no real account state.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
