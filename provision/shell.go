package provision

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The shell a provisioned account gets is RESOLVED on the host, never assumed
// from a conventional FHS path. `/bin/bash` and `/usr/sbin/nologin` are a
// Debian/Ubuntu layout, not a Unix guarantee: on NixOS neither file exists (the
// real binaries live at `/run/current-system/sw/bin/bash` and
// `/run/current-system/sw/bin/nologin`), so `useradd --shell /bin/bash` merely
// WARNS and lands an account whose login shell is not there.
//
// This is the same rule anonctl applies to the binaries it bakes into systemd
// units (internal/systemd.Resolver, anonctl docs/adr/0005): resolve the NAME, use
// the answer VERBATIM, fail loudly when it cannot be resolved. It is ONE code
// path on every distro, never a distro check.

// loginShellNames are the shells tried, in order, for the anon LOGIN account: a
// real interactive shell the operator drops into via `use`.
var loginShellNames = []string{"bash", "sh"}

// nologinShellNames are the shells tried, in order, for the shim SERVICE account:
// a shell whose only job is to refuse a login.
var nologinShellNames = []string{"nologin"}

// loginShellFallbacks are conventional login-shell paths accepted ONLY when the
// file is really there (they are stat'ed, never assumed). `/bin/sh` is the one
// defensible last resort: POSIX-conventional and present on Debian AND NixOS.
var loginShellFallbacks = []string{"/bin/sh"}

// nologinShellFallbacks are conventional nologin paths accepted ONLY when the file
// is really there. There is NO safe generic substitute for nologin, so when none
// of these exists the resolution FAILS LOUDLY rather than inventing a shell: a
// wrong value here would be written into passwd and only discovered later.
var nologinShellFallbacks = []string{"/usr/sbin/nologin", "/sbin/nologin"}

// ShellResolver turns a shell NAME into the absolute path written into the
// account's passwd entry. Both lookups are injectable so the resolution rules are
// unit-testable with no root and with NO dependency on what happens to be
// installed on the test machine - the same discipline as the Runner seam for
// mutations, and the same shape as anonctl's internal/systemd.Resolver.
type ShellResolver struct {
	// Look resolves a bare name against $PATH; exec.LookPath when nil.
	Look func(name string) (string, error)
	// Stat reports a path's file info; os.Stat when nil. Used ONLY to check that a
	// conventional fallback path really exists before accepting it.
	Stat func(path string) (os.FileInfo, error)
	// ShellsFile is the host's declared login-shell list; DefaultShellsFile when
	// empty. It is consulted ONLY to prefer a host-declared ALIAS for the file the
	// $PATH lookup already found (see preferDeclaredAlias), never as a source of
	// shells in its own right.
	ShellsFile string
}

// DefaultShellsFile is the host's own list of valid login shells. Both Debian and
// NixOS maintain it, so reading it is not a distro check.
const DefaultShellsFile = "/etc/shells"

// Shells is the package-level resolver seam provisioning uses, mirroring the
// WriteLoginEnv seam: production leaves it zero-valued (exec.LookPath + os.Stat)
// and a test replaces it to drive an exact, host-independent resolution.
var Shells = ShellResolver{}

func (s ShellResolver) look(name string) (string, error) {
	if s.Look != nil {
		return s.Look(name)
	}
	return exec.LookPath(name)
}

func (s ShellResolver) stat(path string) (os.FileInfo, error) {
	if s.Stat != nil {
		return s.Stat(path)
	}
	return os.Stat(path)
}

func (s ShellResolver) shellsFile() string {
	if s.ShellsFile != "" {
		return s.ShellsFile
	}
	return DefaultShellsFile
}

// preferDeclaredAlias returns a path from the host's /etc/shells that names the
// SAME FILE as candidate, when one exists, and otherwise candidate unchanged.
//
// This exists because "use the $PATH entry verbatim" is NECESSARY but not
// SUFFICIENT. The verbatim rule assumes the $PATH entry is the stable alias, and
// on a NixOS box that is only true when $PATH is the system profile. MEASURED on
// telemaque 2026-09-21, an ordinary session had a store path EARLIER in $PATH than
// the system profile:
//
//	$ which bash
//	/nix/store/yisa2lg...-bash-interactive-5.3p9/bin/bash
//	$ head -1 /etc/shells
//	/run/current-system/sw/bin/bash            (a symlink to exactly that file)
//
// So exec.LookPath hands back a garbage-collectable store path through the $PATH
// ENTRY rather than through symlink resolution - the same delayed-action bomb by a
// different route, and one a caller's environment (a nix-shell, a service unit,
// a dev session) can introduce without anything in anoncore changing.
//
// /etc/shells is the host's OWN statement of which paths name a valid login shell,
// and on NixOS it lists the stable alias FIRST. So: if a declared entry names the
// same file as what $PATH gave us, prefer the declared entry. Three properties
// make this safe rather than clever:
//
//   - It can only ever swap in a path naming the IDENTICAL binary (compared with
//     os.SameFile, which follows symlinks for the COMPARISON only).
//   - It never RETURNS a resolved target: both candidates are unresolved paths, so
//     the EvalSymlinks trap stays closed.
//   - A missing, unreadable, or non-matching /etc/shells changes nothing (the
//     verbatim $PATH entry stands), so this is a preference, never a dependency.
//
// On Debian /etc/shells declares /bin/bash and the $PATH lookup finds the same
// file, so the identical code returns a conventional Debian path. One code path.
func (s ShellResolver) preferDeclaredAlias(candidate string) string {
	data, err := os.ReadFile(s.shellsFile())
	if err != nil {
		return candidate
	}
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") || !filepath.IsAbs(entry) {
			continue
		}
		if entry == candidate {
			// The lookup already named a declared shell: nothing to prefer.
			return candidate
		}
		if sameFile(entry, candidate) {
			return entry
		}
	}
	return candidate
}

// sameFile reports whether two paths name the same file, following symlinks. Used
// only for COMPARISON; the resolved target is never returned or written to passwd.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// ResolvedShells is the pair of shells one `add` needs: the login account's
// interactive shell and the shim service account's nologin shell.
type ResolvedShells struct {
	// Login is the absolute path to the login account's interactive shell.
	Login string `json:"login"`
	// Nologin is the absolute path to the shim service account's nologin shell.
	Nologin string `json:"nologin"`
}

// Resolve resolves BOTH shells, or fails. `add` calls it BEFORE it creates
// anything, so a host where a shell cannot be resolved is refused while it is
// still UNTOUCHED. That ordering is load-bearing: resolving the nologin shell
// lazily (at shim-creation time) is exactly what leaves the half-provisioned
// residue - a login account that exists, no shim, and no forcing installed.
func (s ShellResolver) Resolve() (ResolvedShells, error) {
	login, err := s.LoginShell()
	if err != nil {
		return ResolvedShells{}, err
	}
	nologin, err := s.NologinShell()
	if err != nil {
		return ResolvedShells{}, err
	}
	return ResolvedShells{Login: login, Nologin: nologin}, nil
}

// LoginShell resolves the interactive shell for the anon login account. The
// result is passed through preferDeclaredAlias, because this is the shell that is
// actually EXECUTED on every login: if its path is garbage-collected the account
// becomes unusable (`use` breaks), so it is worth pinning to the alias the host
// itself declares.
func (s ShellResolver) LoginShell() (string, error) {
	path, err := s.resolve("login shell", loginShellNames, loginShellFallbacks)
	if err != nil {
		return "", err
	}
	return s.preferDeclaredAlias(path), nil
}

// NologinShell resolves the login-refusing shell for the shim service account. It
// is deliberately NOT passed through preferDeclaredAlias: /etc/shells lists valid
// LOGIN shells, and nologin is by definition not one (a NixOS /etc/shells lists
// bash and sh only), so there is nothing there to match against. The asymmetry is
// also harmless in consequence: this shell exists to REFUSE a login and is never
// successfully executed, so a path that later disappears still refuses the login.
// It fails closed, unlike the login shell, which fails the operator.
func (s ShellResolver) NologinShell() (string, error) {
	return s.resolve("nologin shell", nologinShellNames, nologinShellFallbacks)
}

// PreflightShells checks that both shells an `add` will write into passwd can be
// resolved on THIS host, without creating anything. A consumer can call it even
// earlier than `add` does (alongside its own preflights) so a host that cannot
// name a shell is refused before any account, rule, or unit is touched.
func PreflightShells() error {
	_, err := Shells.Resolve()
	return err
}

// resolve implements the shared chain: every NAME against $PATH first, then any
// conventional fallback path that REALLY EXISTS, then a loud error naming
// everything it tried. The error is deliberately verbose: an unresolvable shell
// must be a diagnosable refusal, never a silent bad value in passwd.
//
// NEVER RESOLVE THE SYMLINK. exec.LookPath returns the $PATH entry VERBATIM and
// that is exactly what gets written into the account's passwd shell field. On
// NixOS every tool has two absolute paths:
//
//	/run/current-system/sw/bin/bash                      <- STABLE: repointed on every rebuild
//	/nix/store/<hash>-bash-interactive-5.3p9/bin/bash    <- what EvalSymlinks/realpath/readlink -f gives
//
// The store path is correct the day it is written and WRONG the moment the
// package is updated: the old store path is garbage-collected and the account's
// login shell points at a file that no longer exists - weeks later, with nothing
// in the configuration having changed. /etc/shells on a NixOS box lists the
// STABLE alias, which is the host's own statement of which path to persist.
// filepath.Abs is safe here (it only Cleans an already-absolute path);
// filepath.EvalSymlinks is NOT, and neither is os.Executable (it reads
// /proc/self/exe, which resolves). On Debian the same lookup yields
// /bin/bash or /usr/sbin/nologin and the identical code works, so this is one
// code path, not a distro branch.
func (s ShellResolver) resolve(kind string, names, fallbacks []string) (string, error) {
	for _, name := range names {
		path, err := s.look(name)
		if err != nil {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		return abs, nil
	}
	for _, path := range fallbacks {
		if st, err := s.stat(path); err == nil && !st.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf(
		"provision: cannot resolve a %s for the account: looked for %s on $PATH and for %s on disk; "+
			"install one or put it on $PATH (no conventional path is assumed, because /bin/bash and /usr/sbin/nologin do not exist on every distribution)",
		kind, strings.Join(names, ", "), strings.Join(fallbacks, ", "))
}
