# The anoncore module boundary: shared substrate-agnostic core vs per-tool substrate glue

## Status

Accepted. This is the FOUNDING decision of the `anoncore` module: the hard-to-reverse call this ADR exists to pin.

## Context

`anonctl` is a published, security-critical tool that anonymizes a Unix account's egress by forcing it through a socks5h proxy with per-UID nftables rules. Two sibling tools are planned: `anonbox` (the same account/identity model, but egress enforced by a netcage network namespace instead of nftables) and `anonseed` (a config-seeding tool that writes a program's config into an anonymized home and declares the LAN hole it needs). Both would otherwise need the SAME account-creation, home-seeding, marker, and elevation logic anonctl already has.

Copying that logic into each tool is the exact failure mode to avoid: it is the security-critical, load-bearing hardening (no sudo/wheel grant on the created account, setuid-bit strip on seed, symlink refusal, mode-700 home, the credential-free marker contract). If it is copied, it DRIFTS: a fix or a tightening lands in one tool and not the others, and the weakest copy sets the real security posture. So the shared core is EXTRACTED into one module both consumers import, not vendored.

`anoncore` is its own repo (`github.com/wighawag/anoncore`), NOT a package inside anonctl. Hosting it inside anonctl would make anonctl a library as well as a binary and couple every other tool to anonctl's release cadence and internal layout (a refactor in anonctl's `internal/` would ripple into anonbox). A standalone module has a stable import path and its own version, and neither consumer owns the other. (This mirrors update 5a of the netcage machines-scope design note.)

## Decision

The boundary is drawn at **substrate-agnosticism**: a package belongs in `anoncore` if and only if its behaviour is IDENTICAL whether the egress substrate is anonctl's per-UID nftables forcing or anonbox's netcage namespace.

**Shared core (moved into `anoncore`):**

- `account` - the account-NAME vocabulary (default account, name resolution, shim naming, login-account recognition).
- `provision` - account + dedicated-shim-UID lifecycle behind add/rm/list/status, all mutation behind an injected `Runner` seam (no direct `useradd`).
- `seedhome` - the credential-shedding home seeder (setuid/setgid/sticky strip, symlink refusal, mode-700).
- `marker` - the world-readable, credential-free double-anonymization coordination contract.
- `accountconfig` - the per-account at-rest operational record (endpoint, shim ports, UIDs).
- `endpoint` - socks5h endpoint parse + share-class classification + credential-free-at-rest guard.
- `sudoprobe` - the "account has NO sudo rights" assertion over `sudo -l -U` output.
- `ui` - the tiny per-stream terminal color layer.

**Per-tool substrate glue (STAYS in the consuming tool):** anonctl's `nftables`, `forcing`, `shim`, `lanexempt`, `systemd` (per-UID kernel forcing + its shim/units), and `defaults` (anonctl-config-specific). anonbox will supply its own (netcage argv); anonseed needs none of these.

The dependency direction is one-way and enforced by having ZERO import of any anonctl package inside `anoncore`: **anonctl imports anoncore, never the reverse.** `anoncore` is a clean lower layer.

### The `provision -> cli` layering inversion (resolved)

`anonctl/internal/provision/provision.go` (SOURCE, not just a test) imported `anonctl/internal/cli` for exactly three symbols: `cli.ShimAccount`, `cli.DefaultAccount`, and (in the integration test) `cli.ResolveAccount`. This was a layering inversion: core provisioning logic depending on anonctl's COMMAND SURFACE, which is anonctl-specific and does not belong in a shared core.

Resolution: **move the shared piece down, invert the rest.** The three symbols are pure account-NAME vocabulary (`anon`, `anon-<name>`, `<account>-shim`) that is genuinely shared substrate-agnostic language, so they were extracted DOWN into a new `anoncore/account` package. The rest of `cli` (argv parsing, the verb table, the flag grammar) is anonctl's command surface and STAYED in anonctl. anonctl's `internal/cli` now re-exports `DefaultAccount`/`ResolveAccount`/`ShimAccount` from `anoncore/account`, so anonctl's own callers are unchanged and there is a SINGLE source of truth for the naming (no drift). `provision.isAnonLogin` (which also spelled the `anon-` prefix rule inline) now delegates to `account.IsAnonLogin`.

The alternatives considered and rejected: leaving a thin anonctl-side adapter (would keep the naming duplicated, inviting drift) and passing the names in as parameters on every call (churns every `provision` call site for vocabulary that is genuinely shared, not caller-specific).

### The verify split (deferred, deliberately)

anonctl's `internal/verify` is substrate-SPECIFIC in the load-bearing part: it asserts the nftables per-UID forcing, the shim closures, and the UID-transition probes. Its account-layer assertion helpers and its `--json` envelope / assertion-naming machinery MIGHT be shareable, but the future consumers' verify stories differ (anonbox delegates the egress proof to `netcage verify`; anonseed does not prove egress at all), so extracting the JSON/assertion scaffolding NOW would guess at needs that are not yet pinned.

Decision: **`verify` stays entirely in anonctl for this pass.** It is the minimal, clearly-correct split. `verify` depends on `provision` (which moved), and that is fine because anonctl imports anoncore. Extracting only the substrate-agnostic assertion/JSON scaffolding is left as a FOLLOW-UP, to be driven by anonbox's and anonseed's actual verify shapes rather than guessed at here.

## Consequences

- The security-critical hardening now lives in ONE place; a tightening lands for every `anon*` tool at once and cannot drift between them.
- `anoncore` is unpublished for now; anonctl consumes it via a `replace github.com/wighawag/anoncore => ../anoncore` directive in its `go.mod`. That directive is a temporary bridge to be replaced by a real version tag once `anoncore` is released.
- The injected-`Runner` test discipline survived the move intact: unit tests travel WITH their packages and still pass against the fake runner with no root; the `integration`-tagged tests travel too and still SKIP without root.
- `verify` staying in anonctl means anonctl still owns its own end-to-end proof; the shared-scaffolding question is reopened, not answered, when a second consumer needs it.
- The `/etc/anonctl/...` default paths in the moved `marker`/`accountconfig` packages are anonctl's contract DEFAULTS, reachable behind each package's `BaseDir` lever; a different consumer (anonbox) overrides `BaseDir` rather than inheriting anonctl's `/etc` layout. The defaults were kept as-is to preserve anonctl's published on-disk contract byte-for-byte.

## References

- netcage design note `work/notes/ideas/netcage-machines-scope-fork.md` (update 5a: why anoncore is its own repo; the "Open decisions" note on the module boundary and the verify split).
- anonctl ADR 0009 (retroactive note that the core was extracted to anoncore).
