# The anon account carries no sudo/wheel, and a distinct shim UID is the sole egress-dialer

## Status

Accepted. This is the core threat-model decision the `provision` package embodies: the closure of the UID-transition escape.

## Context

`anon*` tools force an account's egress through a socks5h proxy with per-UID kernel rules: only the intended UID's traffic is forced. The sharpest residual threat to that model is a **UID transition** — if the anon account can become a DIFFERENT UID (via `sudo`, a setuid binary, `pkexec`, a wheel-group grant), it can open a socket owned by that other UID, whose traffic is NOT forced, and leak straight past the per-UID rules. So "the anon account must not be able to transition UID" is a load-bearing security invariant, not a nicety.

A naive `useradd` of a normal login user is close to safe, but the invariant must be POSITIVELY held and asserted, not assumed. Separately, SOMETHING must dial the upstream endpoint, and that dialer's UID is exactly the one the per-UID rules must single out; conflating it with the login account's UID would blur which UID is "allowed upstream".

## Decision

Two coupled provisioning rules:

1. **The login account is granted NO sudo/wheel.** `provision` creates the `anon` / `anon-<name>` account with no `--groups` grant, and POSITIVELY asserts (in tests) that no provisioning command grants sudo/wheel. The no-grant is not left implicit in `useradd`'s defaults; it is an asserted invariant that a future change cannot silently regress.
2. **A distinct dedicated shim UID is the ONLY egress-dialer.** Alongside the login account, `provision` creates a separate `<account>-shim` service account (`--system`, `nologin`). That shim UID runs the socks shim and is the one and only UID later allowed to dial the upstream endpoint. Separating it from the login UID makes the per-UID forcing rules unambiguous about which UID egress is permitted for, and keeps the login account (which a human uses) off the privileged-egress path.

This is the shared, substrate-agnostic account shape: it holds identically whether the egress substrate is anonctl's nftables forcing or anonbox's netcage namespace, which is why it lives in `anoncore/provision` rather than a consumer (ADR-0001). All mutation goes through the injected `Runner` seam so the shape is unit-testable with no real `useradd`; the real behaviour is exercised behind the `integration` tag.

## Considered options

- **Explicitly pass `--groups ""`** (rejected as a no-op / risk): `useradd`'s default already grants no supplementary groups, so adding an empty `--groups` changes nothing and only risks surprising behaviour; the invariant is better held by a positive test assertion than by a redundant flag.
- **Run the shim as the login account's own UID** (rejected): would make the "which UID is allowed upstream" question ambiguous and put the human-used login account on the privileged-egress path. A dedicated `--system nologin` shim UID keeps the boundary crisp.
- **Rely on `useradd` defaults without asserting the invariant** (rejected): a silent future regression (someone adding a group grant) would reopen the escape with no test catching it.

## Consequences

- The UID-transition escape is closed at provisioning time and guarded by a positive assertion, so a regression fails a test rather than silently weakening the security posture.
- The dedicated shim UID gives the per-UID forcing rules an unambiguous target and is coordinated across tools via the credential-free marker contract.
- The sudo half of the UID-transition vector is verified at runtime by the `sudoprobe` classifier (ADR-0002).

## References

- Recorded reasoning: anonctl work-session `harden-anon-account-against-uid-transition` (the no-`--groups` decision, the shim-UID separation, the rejected PATH/`--groups ""` mechanisms), and the founding module-boundary ADR-0001.
- `provision/provision.go` (the account + shim-UID lifecycle); `docs/adr/0002-sudo-absence-read-from-output-not-exit-code.md` (the runtime sudo assertion).
