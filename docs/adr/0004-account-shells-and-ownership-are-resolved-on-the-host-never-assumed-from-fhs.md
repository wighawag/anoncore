# Account shells and file ownership are resolved on the host, never assumed from FHS

## Status

Accepted, 2026-09-21. Supersedes no earlier decision; it corrects three unrecorded FHS assumptions that `provision` and `seedhome` shipped with.

## Context

`anoncore` provisioning encoded the Debian/Ubuntu filesystem layout in three places, in each case as a literal string that looked like a constant but was really a guess about the host:

1. `chown <account>:<account>` (the login-env write, and every seeded path) assumed a **user-private group** of the same name as the account exists. That is the Debian convention `USERGROUPS_ENAB yes`, where `useradd` creates a per-user group.
2. `useradd --shell /bin/bash` for the login account.
3. `useradd --shell /usr/sbin/nologin` for the shim service account.

MEASURED on a NixOS host (telemaque, 2026-09-21), all three are wrong. NixOS sets `GROUP=100` in `/etc/default/useradd`, so `useradd` places the account in the shared `users` group and creates no per-user group at all (`getent group anon-livetest` returns nothing), and none of `/bin/bash`, `/usr/sbin/nologin`, `/sbin/nologin`, `/bin/false` exists. The observed failure was:

```
anonctl: add: write login env for "anon-livetest": chown "/home/anon-livetest/.profile" to anon-livetest: exit status 1: chown: invalid group: 'anon-livetest:anon-livetest'
```

The three failures differ sharply in how they announce themselves, and that is the reason this is worth recording rather than just patching:

- The **chown** failed loudly, but only AFTER the login account had been created, leaving a **half-provisioned account**: login account present, no shim, no forcing installed. The residue, not the message, is the real damage.
- The **login shell** fails SILENTLY. `useradd` merely warns about a missing shell and creates the account anyway, so the account lands with a login shell that is not there and the failure surfaces later, at `use`, far from its cause.
- The **nologin shell** fails CLOSED (a missing shell prevents login), so it was sloppy rather than dangerous.

## Decision

**Resolve, never assume; and refuse before mutating.**

1. **Ownership uses the trailing-colon `chown` operand `<account>:`** (`account.ChownOperand`). Per coreutils, a colon with no group name makes that user the owner and sets the group to *that user's login group*, so the group is whatever the host actually gave the account: the per-user group on Debian, `users` on NixOS. No group lookup, no branch.
2. **Both shells are resolved through an injectable `provision.ShellResolver`** (defaulting to `exec.LookPath` + `os.Stat`), mirroring anonctl's `internal/systemd.Resolver`. Chain: each NAME against `$PATH` in order, then any conventional path that is STAT'ed and really exists, then a loud error naming everything it tried. `/bin/sh` is the login shell's last resort (present on both distros); the nologin shell has no safe generic substitute, so it FAILS LOUDLY instead of guessing.
3. **The resolved path is used VERBATIM. Never `filepath.EvalSymlinks`.** On NixOS every tool has a STABLE alias (`/run/current-system/sw/bin/bash`, repointed on every rebuild) and a store path (`/nix/store/<hash>-bash-interactive-5.3p9/bin/bash`, what `EvalSymlinks`/`realpath`/`readlink -f` return). The store path is correct the day it is written and WRONG the moment the package is updated: it is garbage-collected and the account's passwd shell field points at a file that no longer exists, weeks later, with nothing in the configuration having changed. `filepath.Abs` is safe (it only `Clean`s an already-absolute path); `os.Executable` is NOT (it reads `/proc/self/exe`, which resolves).
4. **Verbatim is necessary but NOT SUFFICIENT, so a host-declared alias is preferred for the LOGIN shell.** Measured on the same host: `which bash` returned a `/nix/store/...` path, because a store path preceded `/run/current-system/sw/bin` in that session's `$PATH`. The time bomb arrives through the caller's ENVIRONMENT rather than through symlink resolution, and no discipline inside `exec.LookPath` can prevent it. `/etc/shells` is the host's own statement of which path names a valid login shell and lists the stable alias FIRST, so an entry naming the SAME FILE (compared with `os.SameFile`, which follows symlinks for the COMPARISON only) is preferred over the `$PATH` entry. The swap can only ever substitute a path for the identical binary, never a resolved target, and a missing or non-matching `/etc/shells` changes nothing.
5. **`Add` resolves both shells BEFORE the first mutation.** A host that cannot name a shell is refused while it is still untouched, which is what prevents the half-provisioned residue. `PreflightShells` exposes the same check to a consumer that wants to refuse even earlier, alongside its own preflights.

**No distro check anywhere.** One resolution path runs on Debian and NixOS alike, exactly as anonctl's unit-binary resolution does.

## Considered options

- **Look the account's group up ourselves** (`id -gn <account>`, or parse `/etc/group`), rejected: it adds a command and a parse to get an answer coreutils already computes correctly from the trailing colon.
- **Branch on the distribution** (read `/etc/os-release`), rejected: the constraint that produced the original bug. A distro check is a guess with more steps, and it is wrong on the next distribution nobody tested.
- **Fall back to `false` for the nologin shell**, rejected: it IS fail-closed, but it writes an unverified shell into passwd and loses the "This account is currently not available" message. An unresolvable nologin shell is rare and diagnosable; guessing makes it neither.
- **`filepath.EvalSymlinks` to "normalise" the resolved path**, rejected: this is the delayed-action bug, and it is the one most likely to be reintroduced by someone tidying the code, which is why `TestShellResolverReturnsTheLookupPathVerbatimNeverTheSymlinkTarget` pins it with a fake store layout.
- **Trust `exec.LookPath` alone and skip `/etc/shells`**, rejected on evidence: measured, it yields a garbage-collectable store path in an ordinary session on the target host.

## Consequences

- `anonctl add` completes on NixOS, and a host that genuinely cannot provide a shell is refused with an account-free box rather than a half-built one.
- The rules are unit-testable with no root and no dependency on what is installed on the test machine: resolution flows through the injected `Look`/`Stat`/`ShellsFile` seams, exactly as mutations flow through `Runner`. Every test asserts ARGUMENTS, not effects on a real system; the real host behaviour stays behind the `integration` tag, which now also asserts that the shell written into passwd EXISTS.
- The nologin shell keeps the `$PATH` answer verbatim with no `/etc/shells` preference, because `/etc/shells` lists LOGIN shells only and a vanished nologin path still refuses the login.
- One assumption of the same class is deliberately NOT fixed here: `provision.LoginPATH` is the FHS literal `/usr/local/bin:/usr/bin:/bin`, which is nearly empty on NixOS. Unlike the three above it is not a mechanical fix, because its security purpose (omit the sbin dirs holding setuid network binaries) does not translate to a distribution that puts every binary in one directory. Captured as `work/notes/observations/login-path-is-an-fhs-assumption-that-empties-on-nixos.md`.

## References

- `provision/shell.go` (the resolver), `account/account.go` (`ChownOperand`), `provision/shell_test.go`, `provision/provision_test.go`, `seedhome/seedhome_test.go`.
- anonctl `internal/systemd.Resolver` and anonctl `docs/adr/0005-reboot-persistence-and-boot-invariant.md`, which record the same verbatim-path rule for binaries baked into systemd units. This ADR applies it to the passwd shell field.
- Measurements: NixOS host telemaque, 2026-09-21 (`anonctl add livetest` as root; `/etc/default/useradd` `GROUP=100`; `getent group anon-livetest` empty; `which bash` returning a store path; `/etc/shells` listing the stable alias first).
