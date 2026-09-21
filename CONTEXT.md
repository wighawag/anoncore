# CONTEXT — anoncore domain language

The domain glossary for `anoncore`. Agents and skills use THIS vocabulary when naming modules, tests, and discussing the system. Architectural rationale lives in `docs/adr/` (decisions); product framing lives in `work/specs/`.

## What anoncore is

`anoncore` is the shared, substrate-AGNOSTIC account/seed/marker/elevation core library for the `anon*` tool family (`anonctl` today; planned `anonbox`, `anonseed`). It is a library, not a binary: it has no `main` and ships no command. It holds the security-critical, substrate-independent logic (account provisioning with no sudo/wheel grant, seed-home hardening, the credential-free marker contract, endpoint parsing/classification, the sudo-rights probe, terminal UI helpers) so that this hardening cannot silently DRIFT between the tools that import it. The per-tool egress substrate glue (anonctl's per-UID nftables forcing, anonbox's netcage namespace) stays in each tool's own repo.

## Core domain terms

- **account** — the substrate-agnostic account-NAME vocabulary (`anon` default, `ResolveAccount`, `ShimAccount`, `IsAnonLogin`); the shared naming language provisioning builds on.
- **provision** — the account + dedicated-shim-UID lifecycle behind add/rm/list/status, with all system mutation behind an injected **`Runner` seam** so it is unit-testable against a fake with NO real `useradd`.
- **seed-home** — the credential-shedding home seeder: strips setuid/setgid/sticky bits on copy, refuses symlinks, writes mode-700. Load-bearing for "an anonymized home must not carry a uid-transition escape".
- **marker** — the double-anonymization coordination contract: the versioned, credential-free JSON a sibling tool reads to detect "this account is already kernel-anonymized" and skip re-forcing a proxy.
- **accountconfig** — the per-account at-rest operational record (endpoint host:port + share-class, shim ports, UIDs) a tool re-applies forcing from.
- **endpoint** — socks5h endpoint parsing, share-class classification, and the credential-free-at-rest guard.
- **sudoprobe** — classifies `sudo -l -U <account>` output to assert an account has NO sudo rights (the hardened, expected state).
- **ui** — the tiny per-stream terminal color/styling layer (TTY + `NO_COLOR`/`FORCE_COLOR` aware) so the `--json` path stays byte-plain.
- **shell resolution** — the `provision.ShellResolver` seam that turns a shell NAME (`bash`, `nologin`) into the absolute path written into passwd, by asking the host rather than assuming an FHS path. Its rules: resolve, never assume; use the lookup result VERBATIM (never `filepath.EvalSymlinks`, which yields a garbage-collectable `/nix/store` path); prefer an `/etc/shells` entry naming the same file for the LOGIN shell; fail LOUDLY rather than guess; and resolve before the first mutation so a refusal leaves no half-provisioned account. One path on every distribution, never a distro check. See `docs/adr/0004-*`.
- **chown operand** — `account.ChownOperand`: the trailing-colon form `<account>:`, which gives a path to the account's OWN login group instead of assuming a same-named user-private group exists (it does not on NixOS). The shared spelling for every `chown` in the core.
- **Runner seam** — the injected system-mutation interface that lets provisioning/seed-home be tested against a fake with no real `useradd`/`setpriv`; the real behaviour lives behind the `integration` build tag and needs root.
- **integration tag** — real `useradd`/`userdel`/`setpriv` behaviour behind `-tags integration`; those bodies SKIP (not fail) when not root, so a plain `go test ./...` is fully hermetic.
- **promptGuidance** — the per-repo NUDGE namespace in `dorfl.json` whose members (currently just `testFirst`) strengthen the wording in the worker's in-band prompt. NOT a gate: the `verify` step is still the only acceptance bar. Omitted ⇒ off.
- **work/ contract** — the on-disk system this repo uses, defined by the reference docs in **`work/protocol/`** (copied here by `setup`): `WORK-CONTRACT.md` (the contract), `CLAIM-PROTOCOL.md`, `REVIEW-PROTOCOL.md`, `TASKING-PROTOCOL.md`, `SURFACE-PROTOCOL.md`, `task-template.md`, `spec-template.md`, `ADR-FORMAT.md`. Three REGIME umbrellas — `notes/` (capture buckets), `tasks/` (the build board), `specs/` (the spec lifecycle) — plus top-level `questions/` and `protocol/`. One markdown file per item, status = the folder it lives in (never a field). Capture buckets: `notes/ideas/` (proposed), `notes/observations/` (spotted, unverified, append-only), `notes/findings/` (verified external/domain ground truth, each with a `source:`). ADRs (`docs/adr/`, format in `work/protocol/ADR-FORMAT.md`) record what WE decided and why. The module-boundary decision is pinned in `docs/adr/0001-module-boundary-shared-core-vs-per-tool-substrate.md`.

## Conventions

Standing per-change rules agents must follow in this repo.

<!-- No standing per-change rule (changeset/CHANGELOG/news fragment) declared for this repo. Add yours here, or delete this section. For enforcement, wire your own check into the `dorfl.json` `verify` gate. -->

## Skills this repo uses

- Required: `setup` (onboarding/migration), `to-spec`, `to-task`.
- Recommended: `review`, `grill-me`.
