---
title: How NixOS differs from Debian for anon account provisioning (groups, shells, declarative users)
slug: nixos-account-provisioning-ground-truth
source: 'measured directly on NixOS host telemaque, 2026-09-21: `anonctl add livetest` as root, /etc/default/useradd, getent passwd/group, which bash, /etc/shells, and stat of the FHS paths. Re-verify against a NixOS release newer than the one on that box before trusting it for a future release.'
---

## What this describes

The EXTERNAL ground truth about NixOS that `anoncore`'s account provisioning has to hold against. It is not a description of our own code (that is `CONTEXT.md` and `docs/adr/0004-*`); it is what the host does, which our code must stop assuming.

## Groups: there is no user-private group

NixOS sets `GROUP=100` in `/etc/default/useradd`, so `useradd` puts a new account in the shared `users` group and creates NO per-user group of the same name. Debian/Ubuntu do the opposite (`USERGROUPS_ENAB yes` creates one).

Measured:

```
anon-livetest:x:1002:100::/home/anon-livetest:/bin/bash
uid=1002(anon-livetest) gid=100(users) groups=100(users)
getent group anon-livetest        ->  (nothing)
```

Consequence: `chown <account>:<account>` fails with `chown: invalid group`. The portable operand is the trailing colon `<account>:`, which coreutils resolves to the user's own login group on both.

## Shells: the FHS paths do not exist

Measured on the box: `/bin/bash` MISSING, `/usr/sbin/nologin` MISSING, `/sbin/nologin` MISSING, `/bin/false` MISSING. `/bin/sh` EXISTS (it is bash). The real tools are `/run/current-system/sw/bin/bash` and `/run/current-system/sw/bin/nologin`.

`useradd --shell <missing path>` only WARNS; it creates the account anyway. So an assumed shell path is a silent bad value in passwd, discovered later at login.

## Two absolute paths per tool, and only one of them survives an update

```
/run/current-system/sw/bin/bash                          STABLE: repointed on every rebuild
/nix/store/yisa2lg...-bash-interactive-5.3p9/bin/bash    what EvalSymlinks/realpath/readlink -f return
```

The store path is garbage-collected when the package is updated. Anything PERSISTED (a passwd shell field, a systemd `ExecStart`) must use the stable alias. `/etc/shells` on the box lists the stable alias FIRST, then the store path, which is the host's own statement of which to prefer:

```
/run/current-system/sw/bin/bash
/run/current-system/sw/bin/sh
/nix/store/yisa2lg...-bash-interactive-5.3p9/bin/bash
/nix/store/yisa2lg...-bash-interactive-5.3p9/bin/sh
/bin/sh
```

**`exec.LookPath` does not guarantee the stable one.** It returns the `$PATH` ENTRY verbatim, and an ordinary session on that host had a store path EARLIER in `$PATH` than `/run/current-system/sw/bin`, so `which bash` returned the store path. Whether a caller gets the stable alias depends on the environment anoncore is invoked from (a login shell, a `nix-shell`, a service unit), which anoncore does not control.

Also note `/run/current-system/sw/bin/sh` and `.../bash` are THE SAME FILE on that host, so an inode comparison legitimately treats `sh` and `bash` as interchangeable there.

## `users.mutableUsers = false` deletes accounts that are not declared

A separate NixOS behaviour, found downstream of the provisioning bugs and NOT fixable in anoncore: when a host sets `users.mutableUsers = false`, the activation script reconciles the account table against the Nix configuration and REMOVES accounts that the configuration does not declare. An imperatively created account (which is what `useradd` makes, and therefore what `anonctl add` makes) does not survive the next `nixos-rebuild switch`.

Consequence for the anon* tools: on such a host, correct provisioning is necessary but NOT sufficient. The account, its shim, and their UIDs are transient, which also undermines anything keyed to those UIDs (the per-UID forcing rules). Handling it at all would mean emitting declarative configuration for the operator to adopt, or detecting the setting and refusing with an explanation, rather than silently creating an account that will disappear. That is a consumer-level (anonctl) decision, not a shared-core one.

Not measured on that box: whether the activation removes the home directory as well, and exactly which activation phase does the removal. Verify before designing around it.
