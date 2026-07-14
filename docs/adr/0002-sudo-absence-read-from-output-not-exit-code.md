# Sudo-absence is decided from `sudo -l -U` OUTPUT, never the exit code

## Status

Accepted. This is the load-bearing correctness rule of the `sudoprobe` package, shared by both sides of the sudo UID-transition vector.

## Context

`anoncore` must be able to ASSERT that a provisioned `anon` account has NO sudo rights: sudo is a UID-transition vector (an account that can `sudo` can escape its per-UID egress forcing), so "has this account any sudo rights?" is a security-critical question that both the PROVE side (`provision`'s status probe) and, in anonctl, the ASSERT side (`verify`'s no-uid-transition-egress vector) must answer.

The obvious implementation reads the exit code of `sudo -l -U <account>`. That is WRONG, and silently so. An observed real `sudo` build (1.9.16p2) prints the decisive "not allowed to run sudo" text yet exits `0` for a no-rights account. An exit-code-only read of that build reports "this account CAN sudo" for an account that in fact cannot: a false alarm that would flag a correctly-hardened account as unsafe. The inverse (a build that exits non-zero for a benign reason) could equally produce a false "no sudo", which is the more dangerous direction: falsely certifying an account safe.

## Decision

`sudoprobe.ParseOutput` classifies the `sudo -l -U <account>` OUTPUT into a three-valued `Verdict`, WITHOUT trusting the exit code:

- **`Denied`** — the output carries the decisive "not allowed to run sudo" negative. No sudo rights, whatever the exit code.
- **`Granted`** — the output lists permitted commands. Has sudo, whatever the exit code.
- **`Unknown`** — the output is empty/ambiguous/unparseable, or the probe could not run. Surfaced HONESTLY as not-conclusive, NEVER collapsed into a false `Denied` or a false `Granted`.

Precedence is **deny-first**: if the not-allowed negative is present the account has no rights even on a build that also prints noise. The parse is PURE (no exec, no root) so it is exhaustively unit-testable against real-shaped fixtures; each consuming package owns the exec seam that FEEDS this parse. The logic lives in ONE package so the provision side and the verify side cannot drift.

## Considered options

- **Read the exit code** (rejected): false-alarms on the observed lenient exit-0 build; worse, an exit-code read could false-certify an account as safe. The exit code is not a trustworthy signal across sudo builds.
- **Two-valued (has-sudo / no-sudo) with a guess on ambiguity** (rejected): any guess on unparseable output is a guess in a security-critical direction. A false "no sudo" certifies an unsafe account; a false "has sudo" blocks a safe one. Honest `Unknown` refuses to guess either way.

## Consequences

- The verdict is trustworthy across sudo builds that lie via their exit code.
- `Unknown` is a real outcome callers must handle (e.g. `status` reports no decisive sudo verdict rather than printing a false line); it is surfaced, not hidden.
- Because the parse is pure and shared, the prove side and the assert side stay in lockstep by construction.

## References

- Recorded reasoning: anonctl work-sessions `harden-sudo-absence-probe`, `fix-verify-sudovector-exit-code`, `status-sudo-probe-must-be-noninteractive` (the lenient exit-0 case was observed in a real build, 1.9.16p2; noted in anonctl's `work/notes/findings/e2e-binary-revalidation-2.md`).
- `sudoprobe/sudoprobe.go` (the classifier); `provision` (the prove-side seam that feeds it).
