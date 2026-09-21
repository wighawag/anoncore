package provision_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/provision"
)

// notFound is the error a $PATH lookup returns for a binary that is not there.
var notFound = errors.New("executable file not found in $PATH")

// lookOnly builds a fake $PATH lookup that resolves exactly the given
// name -> path map and reports every other name as absent. It is the seam that
// makes shell resolution testable with NO root and NO dependency on what happens
// to be installed on the machine running the tests.
func lookOnly(found map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if p, ok := found[name]; ok {
			return p, nil
		}
		return "", notFound
	}
}

// statNone is a fake stat that reports every conventional fallback path as
// absent, so a test can prove what happens on a host where NO FHS path exists
// (the NixOS shape: no /bin/bash, no /usr/sbin/nologin, no /sbin/nologin).
func statNone(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

// noShellsFile returns a path where no /etc/shells exists, so a test that is not
// about the declared-alias preference never reads the REAL host's /etc/shells.
// Leaving ShellsFile unset makes a test host-dependent: on the NixOS box that
// produced this bug, /etc/shells declares that `sh` and `bash` are the SAME FILE,
// so the preference legitimately rewrites one into the other and an unrelated
// assertion fails for a reason that has nothing to do with what it is testing.
func noShellsFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-etc-shells")
}

// nixStoreLayout builds a FAKE Nix-shaped tree: a REAL file at
// <root>/nix/store/<hash>-<pkg>/bin/<name> and a SYMLINK to it at
// <root>/run/current-system/sw/bin/<name>. It returns the (stable) symlink path
// and the (store) target path. This is the exact two-path shape a NixOS host
// presents, reproduced hermetically in a temp dir.
func nixStoreLayout(t *testing.T, name, pkg string) (stable, store string) {
	t.Helper()
	root := t.TempDir()
	storeDir := filepath.Join(root, "nix", "store", pkg, "bin")
	stableDir := filepath.Join(root, "run", "current-system", "sw", "bin")
	for _, d := range []string{storeDir, stableDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", d, err)
		}
	}
	store = filepath.Join(storeDir, name)
	if err := os.WriteFile(store, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write %q: %v", store, err)
	}
	stable = filepath.Join(stableDir, name)
	if err := os.Symlink(store, stable); err != nil {
		t.Fatalf("symlink %q -> %q: %v", stable, store, err)
	}
	return stable, store
}

// TestShellResolverReturnsTheLookupPathVerbatimNeverTheSymlinkTarget is the
// REGRESSION PIN for the delayed-action half of the NixOS bug, and it is the one
// rule most likely to be reintroduced by someone "tidying up" the resolution code.
//
// On NixOS every tool has TWO absolute paths:
//
//	/run/current-system/sw/bin/bash                      STABLE, repointed on every rebuild
//	/nix/store/<hash>-bash-interactive-5.3p9/bin/bash    what EvalSymlinks/realpath/readlink -f returns
//
// exec.LookPath returns the $PATH entry VERBATIM (the stable one) and
// filepath.Abs preserves it. filepath.EvalSymlinks would return the store path,
// which is correct the day the account is provisioned and WRONG the moment bash
// is updated: the store path is garbage-collected and the account's passwd shell
// field points at a file that no longer exists. /etc/shells on a NixOS box lists
// the STABLE alias, which is the host's own statement of which path to persist.
//
// The fixture is a REAL symlink to a REAL file, and the test asserts BOTH that
// the returned path is the symlink AND that the symlink genuinely resolves
// elsewhere - so it cannot pass vacuously on a layout with nothing to resolve.
// (Proven non-tautological by swapping filepath.Abs for filepath.EvalSymlinks in
// ShellResolver.resolve: this test then fails with the /nix/store path, while
// every other test in the package still passes.)
func TestShellResolverReturnsTheLookupPathVerbatimNeverTheSymlinkTarget(t *testing.T) {
	cases := []struct {
		kind    string
		name    string
		pkg     string
		resolve func(provision.ShellResolver) (string, error)
	}{
		{
			kind:    "login shell",
			name:    "bash",
			pkg:     "9zk1x0q8mp3r-bash-interactive-5.3p9",
			resolve: provision.ShellResolver.LoginShell,
		},
		{
			kind:    "nologin shell",
			name:    "nologin",
			pkg:     "4h2v7c1l8dn0-shadow-4.17.4",
			resolve: provision.ShellResolver.NologinShell,
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			stable, store := nixStoreLayout(t, tc.name, tc.pkg)

			// Guard the FIXTURE itself: the stable path must really be a symlink pointing
			// somewhere else, otherwise "returned the symlink, not the target" is vacuous.
			target, err := filepath.EvalSymlinks(stable)
			if err != nil {
				t.Fatalf("fixture: EvalSymlinks(%q): %v", stable, err)
			}
			if target == stable {
				t.Fatalf("fixture is not a symlink: %q resolves to itself", stable)
			}
			if target != store {
				t.Fatalf("fixture: %q resolves to %q, want the store path %q", stable, target, store)
			}

			r := provision.ShellResolver{
				Look:       lookOnly(map[string]string{tc.name: stable}),
				Stat:       statNone,
				ShellsFile: noShellsFile(t),
			}
			got, err := tc.resolve(r)
			if err != nil {
				t.Fatalf("%s: %v", tc.kind, err)
			}
			if got != stable {
				t.Errorf("%s = %q, want the VERBATIM $PATH entry %q", tc.kind, got, stable)
			}
			if got == store {
				t.Errorf("%s returned the RESOLVED store path %q; that path is garbage-collected on the next update, leaving the account's passwd shell pointing at a file that no longer exists", tc.kind, got)
			}
			if strings.Contains(got, "/nix/store/") {
				t.Errorf("%s = %q: a resolved store path must never be written into passwd", tc.kind, got)
			}
		})
	}
}

// TestShellResolverPrefersTheFirstNameOnPath pins the ORDER of the login-shell
// chain: bash when it is on $PATH, sh as the next candidate. A host with no bash
// still gets a working interactive shell rather than a refusal.
func TestShellResolverPrefersTheFirstNameOnPath(t *testing.T) {
	r := provision.ShellResolver{
		Look: lookOnly(map[string]string{
			"bash": "/run/current-system/sw/bin/bash",
			"sh":   "/run/current-system/sw/bin/sh",
		}),
		Stat:       statNone,
		ShellsFile: noShellsFile(t),
	}
	got, err := r.LoginShell()
	if err != nil {
		t.Fatalf("LoginShell: %v", err)
	}
	if got != "/run/current-system/sw/bin/bash" {
		t.Errorf("LoginShell = %q, want the bash on $PATH", got)
	}

	// No bash: fall through to sh, still resolved (never assumed).
	r.Look = lookOnly(map[string]string{"sh": "/run/current-system/sw/bin/sh"})
	got, err = r.LoginShell()
	if err != nil {
		t.Fatalf("LoginShell (no bash): %v", err)
	}
	if got != "/run/current-system/sw/bin/sh" {
		t.Errorf("LoginShell (no bash) = %q, want the sh on $PATH", got)
	}
}

// TestShellResolverFallsBackOnlyToAPathThatReallyExists pins the last resort:
// /bin/sh is accepted for the LOGIN shell only after it is STAT'ed, never assumed
// because the string looks conventional. That distinction is the whole bug class:
// `useradd --shell /bin/bash` on NixOS only WARNS, so an assumed path lands in
// passwd and breaks `use` later, while a stat'ed one cannot.
func TestShellResolverFallsBackOnlyToAPathThatReallyExists(t *testing.T) {
	existing := map[string]bool{"/bin/sh": true}
	r := provision.ShellResolver{
		Look:       lookOnly(nil), // nothing on $PATH at all
		ShellsFile: noShellsFile(t),
		Stat: func(path string) (os.FileInfo, error) {
			if existing[path] {
				// Stat something that certainly exists and is not a directory; only the
				// existence + not-a-dir answer is consulted.
				return os.Stat(fileThatExists(t))
			}
			return nil, os.ErrNotExist
		},
	}
	got, err := r.LoginShell()
	if err != nil {
		t.Fatalf("LoginShell: %v", err)
	}
	if got != "/bin/sh" {
		t.Errorf("LoginShell = %q, want the stat'ed /bin/sh last resort", got)
	}

	// With /bin/sh absent too (nothing on $PATH, nothing on disk), resolution must
	// FAIL LOUDLY rather than hand back a conventional-looking string.
	r.Stat = statNone
	if got, err := r.LoginShell(); err == nil {
		t.Errorf("LoginShell = %q, want an error when no shell can be resolved at all", got)
	}
}

// TestNologinShellFailsLoudlyRatherThanGuessing pins the asymmetry between the two
// shells. /bin/sh is a defensible last resort for a LOGIN shell (it exists on
// Debian and NixOS alike), but there is NO equally safe generic stand-in for
// nologin: inventing one would write a shell into passwd that was never verified.
// So an unresolvable nologin is a loud, diagnosable refusal naming what was tried.
func TestNologinShellFailsLoudlyRatherThanGuessing(t *testing.T) {
	r := provision.ShellResolver{Look: lookOnly(nil), Stat: statNone, ShellsFile: noShellsFile(t)}
	got, err := r.NologinShell()
	if err == nil {
		t.Fatalf("NologinShell = %q, want an error: no safe generic substitute exists", got)
	}
	// The error must be diagnosable: it names what it looked for, on $PATH and on disk.
	for _, want := range []string{"nologin", "$PATH", "/usr/sbin/nologin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q; an unresolvable shell must be diagnosable", err, want)
		}
	}
	// A conventional path is still accepted when it REALLY exists (Debian's
	// /usr/sbin/nologin off a root $PATH that happens to omit the sbin dirs).
	r.Stat = func(path string) (os.FileInfo, error) {
		if path == "/usr/sbin/nologin" {
			return os.Stat(fileThatExists(t))
		}
		return nil, os.ErrNotExist
	}
	got, err = r.NologinShell()
	if err != nil {
		t.Fatalf("NologinShell (stat'ed /usr/sbin/nologin): %v", err)
	}
	if got != "/usr/sbin/nologin" {
		t.Errorf("NologinShell = %q, want /usr/sbin/nologin", got)
	}
}

// TestShellResolverNeverAcceptsADirectory guards the fallback stat: a DIRECTORY at
// a conventional path is not a shell.
func TestShellResolverNeverAcceptsADirectory(t *testing.T) {
	dir := t.TempDir()
	r := provision.ShellResolver{
		Look:       lookOnly(nil),
		Stat:       func(string) (os.FileInfo, error) { return os.Stat(dir) },
		ShellsFile: noShellsFile(t),
	}
	if got, err := r.LoginShell(); err == nil {
		t.Errorf("LoginShell = %q, want an error: a directory is not a shell", got)
	}
}

// TestResolveReturnsBothShells covers the pair `add` preflights.
func TestResolveReturnsBothShells(t *testing.T) {
	r := provision.ShellResolver{
		Look: lookOnly(map[string]string{
			"bash":    "/run/current-system/sw/bin/bash",
			"nologin": "/run/current-system/sw/bin/nologin",
		}),
		Stat:       statNone,
		ShellsFile: noShellsFile(t),
	}
	shells, err := r.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if shells.Login != "/run/current-system/sw/bin/bash" || shells.Nologin != "/run/current-system/sw/bin/nologin" {
		t.Errorf("Resolve = %+v, want both resolved $PATH entries verbatim", shells)
	}

	// A missing nologin fails the PAIR, so `add` refuses before it creates anything.
	r.Look = lookOnly(map[string]string{"bash": "/run/current-system/sw/bin/bash"})
	if _, err := r.Resolve(); err == nil {
		t.Errorf("Resolve must fail when the nologin shell cannot be resolved")
	}
}

// fileThatExists returns the path of a real, non-directory file for tests that
// only need stat to say "this exists and is not a directory".
func fileThatExists(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "present")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatalf("write %q: %v", p, err)
	}
	return p
}

// TestLoginShellPrefersTheStableAliasTheHostDeclares covers the case MEASURED on
// telemaque 2026-09-21, which the "use exec.LookPath verbatim" rule does NOT cover
// on its own: the $PATH ENTRY ITSELF was a /nix/store path, because a store path
// preceded /run/current-system/sw/bin in that session's $PATH.
//
//	which bash    -> /nix/store/yisa2lg...-bash-interactive-5.3p9/bin/bash
//	head -1 /etc/shells -> /run/current-system/sw/bin/bash   (symlink to that same file)
//
// Verbatim is still exactly right (never EvalSymlinks), but it is not sufficient:
// the garbage-collection time bomb arrives through the caller's environment rather
// than through symlink resolution. /etc/shells is the host's own declaration of
// which path names a valid login shell, so an entry naming the SAME FILE is
// preferred. The swap is inode-checked, so it can only ever substitute a path for
// the identical binary, and the resolved target is never returned.
func TestLoginShellPrefersTheStableAliasTheHostDeclares(t *testing.T) {
	stable, store := nixStoreLayout(t, "bash", "yisa2lg79zcv-bash-interactive-5.3p9")
	shells := writeShellsFile(t, "# /etc/shells: valid login shells\n"+stable+"\n"+store+"\n/bin/sh\n")

	r := provision.ShellResolver{
		// The lookup returns the STORE path, exactly as the real host did.
		Look:       lookOnly(map[string]string{"bash": store}),
		Stat:       statNone,
		ShellsFile: shells,
	}
	got, err := r.LoginShell()
	if err != nil {
		t.Fatalf("LoginShell: %v", err)
	}
	if got != stable {
		t.Errorf("LoginShell = %q, want the host-declared stable alias %q", got, stable)
	}
	if got == store {
		t.Errorf("LoginShell = %q: a store path is garbage-collected on the next update, which would leave the account with no login shell at all", got)
	}
}

// TestLoginShellKeepsTheLookupPathWhenNothingBetterIsDeclared pins the preference
// as a PREFERENCE, never a dependency: a missing/unreadable /etc/shells, or one
// that declares only OTHER files, leaves the verbatim $PATH entry standing. The
// resolver must never fail, and never substitute, on the strength of that file.
func TestLoginShellKeepsTheLookupPathWhenNothingBetterIsDeclared(t *testing.T) {
	onPath := filepath.Join(t.TempDir(), "bash")
	if err := os.WriteFile(onPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	cases := map[string]string{
		"absent /etc/shells":    filepath.Join(t.TempDir(), "no-such-file"),
		"declares another file": writeShellsFile(t, "/bin/sh\n"+fileThatExists(t)+"\n"),
		"empty and comments":    writeShellsFile(t, "# nothing here\n\n"),
		"relative entries only": writeShellsFile(t, "bash\nsh\n"),
	}
	for name, shells := range cases {
		t.Run(name, func(t *testing.T) {
			r := provision.ShellResolver{
				Look:       lookOnly(map[string]string{"bash": onPath}),
				Stat:       statNone,
				ShellsFile: shells,
			}
			got, err := r.LoginShell()
			if err != nil {
				t.Fatalf("LoginShell: %v", err)
			}
			if got != onPath {
				t.Errorf("LoginShell = %q, want the verbatim $PATH entry %q", got, onPath)
			}
		})
	}
}

// TestNologinShellIgnoresEtcShells pins the deliberate asymmetry: /etc/shells lists
// valid LOGIN shells, which nologin is not, so there is nothing there to match and
// the resolver must not go looking. A nologin path that later disappears still
// refuses the login (it fails CLOSED), unlike a login shell, which would leave the
// operator unable to use the account.
func TestNologinShellIgnoresEtcShells(t *testing.T) {
	stable, store := nixStoreLayout(t, "nologin", "4h2v7c1l8dn0-shadow-4.17.4")
	// A (nonsensical) /etc/shells that DOES declare the alias: even so, the nologin
	// resolution must return the lookup result untouched.
	shells := writeShellsFile(t, stable+"\n")

	r := provision.ShellResolver{
		Look:       lookOnly(map[string]string{"nologin": store}),
		Stat:       statNone,
		ShellsFile: shells,
	}
	got, err := r.NologinShell()
	if err != nil {
		t.Fatalf("NologinShell: %v", err)
	}
	if got != store {
		t.Errorf("NologinShell = %q, want the verbatim lookup %q (/etc/shells is not consulted for a nologin shell)", got, store)
	}
}

// writeShellsFile lays down a fake /etc/shells and returns its path.
func writeShellsFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "shells")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write shells file: %v", err)
	}
	return p
}
