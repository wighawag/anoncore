---
title: provision.LoginPATH is an FHS assumption that leaves a NixOS anon account with almost no commands
slug: login-path-is-an-fhs-assumption-that-empties-on-nixos
---

## What was spotted

`provision.LoginPATH` is the literal `"/usr/local/bin:/usr/bin:/bin"`, written into every freshly created anon account's `~/.profile` as `export PATH=...`. It is the same class of assumption as the three fixed in ADR-0004 (`chown <account>:<account>`, `--shell /bin/bash`, `--shell /usr/sbin/nologin`), and it was found by the same grep, but it was deliberately NOT fixed in that pass.

On the NixOS host measured 2026-09-21 (telemaque), those three directories are essentially empty: `/bin` holds only `sh`, `/usr/bin` holds only `env`, and `/usr/local/bin` does not exist. So an anon account provisioned there gets a login PATH with almost no commands on it: no `ls`, no `git`, no editor, no `pi`. The real binaries live under `/run/current-system/sw/bin`, and per-user tools under the user's Nix profile.

Severity is comparable to the login-shell bug (`use` lands you somewhere unusable), but the account is not BROKEN in the same way: a user can still name binaries by absolute path, and the shell starts.

## Why it was not fixed with the others

Because it is not a mechanical portability fix, and pretending otherwise would quietly discard a security property.

`LoginPATH` is not merely "where the commands are". Its documented job is to OMIT the sbin directories (`/usr/local/sbin`, `/usr/sbin`, `/sbin`) that hold the setuid network binaries the audit flagged (`exim4`, `pppd`, `mount.nfs`): a socket one of those opens carries a DIFFERENT uid and escapes the `meta skuid` forcing. Shrinking the PATH is a partial CLOSE-AT-ADD hardening (it does not remove the binaries, which remain reachable by absolute path), and the residual is documented in the anonctl README threat model.

That hardening is expressed as a DIRECTORY OMISSION, and a directory omission has no meaning on a distribution that puts every binary in a single `/run/current-system/sw/bin`. There is no `sbin` half to leave out. So "make LoginPATH portable" is really the question *what does the setuid-network-binary hardening become on a single-bindir distribution?*, which is a decision, not a substitution.

## Options a decision would have to choose between

- **Resolve the system bin dir the way the shells are now resolved** and accept that on such a host the sbin omission buys nothing, documenting the weakened posture honestly (the hardening degrades where the layout cannot express it).
- **Derive the PATH by FILTERING the host's own PATH** (drop any entry whose name ends in `sbin`), which preserves the intent where it is expressible and is a no-op where it is not.
- **Enumerate the setuid binaries actually present** and address the vector directly rather than through PATH shape, which is stronger but much larger in scope.
- **Leave it and state the limitation**, if the honest conclusion is that PATH shaping was always a weak barrier.

## Where to look

- `provision/provision.go`: `LoginPATH`, `loginEnvContent`, `writeLoginEnv`.
- `provision/provision_test.go`: `TestAddWritesMinimalLoginPATH` asserts the sbin dirs are absent from the constant, so any change must keep or consciously retire that assertion.
- `docs/adr/0004-account-shells-and-ownership-are-resolved-on-the-host-never-assumed-from-fhs.md` (this is called out under Consequences).
- anonctl README threat model, and `work/notes/findings/uid-transition-escape-surface.md` in anonctl.
