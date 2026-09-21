package seedhome_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	acct "github.com/wighawag/anoncore/account"
	"github.com/wighawag/anoncore/seedhome"
)

// fakeRunner records the chown calls the seed issues so the tests assert the
// account ownership WITHOUT running a real chown (which needs root). The copy
// itself is real filesystem I/O into a temp dir, so mode/collision/strip behaviour
// is exercised for real.
type fakeRunner struct{ calls [][]string }

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return "", "", nil
}

// writeFile is a small helper to lay down a template file with a given mode.
func writeFile(t *testing.T, path string, mode os.FileMode, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %q: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %q: %v", path, err)
	}
}

// TestSeedCopiesTreeAndChownsToAccount is the happy path: a nested template lands
// in the home with content preserved, and every written file is chowned to the
// account.
func TestSeedCopiesTreeAndChownsToAccount(t *testing.T) {
	tmpl := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(tmpl, ".bashrc"), 0o644, "export FOO=bar\n")
	writeFile(t, filepath.Join(tmpl, ".config", "app", "conf.toml"), 0o600, "key=1\n")

	r := &fakeRunner{}
	res, err := seedhome.Seed(context.Background(), r, tmpl, home, "anon", false)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if res.Copied != 2 {
		t.Errorf("expected 2 files copied, got %d", res.Copied)
	}
	if got, err := os.ReadFile(filepath.Join(home, ".bashrc")); err != nil || string(got) != "export FOO=bar\n" {
		t.Errorf(".bashrc content = %q, err %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(home, ".config", "app", "conf.toml")); err != nil || string(got) != "key=1\n" {
		t.Errorf("nested conf content = %q, err %v", got, err)
	}
	// Every written path (files AND the directories that hold them) is chowned to the
	// account, via the trailing-colon operand `anon:` (the account's OWN login group,
	// whatever the host gave it - see TestSeedChownDoesNotAssumeAUserPrivateGroup).
	// Chowning the dirs too is load-bearing: a root-run seed's MkdirAll leaves them
	// root-owned, so the account could read the seeded files but not create new
	// entries under a seeded dir (the `pi` EACCES on .pi/agent/).
	chowned := map[string]bool{}
	for _, c := range r.calls {
		if len(c) >= 3 && c[0] == "chown" && c[1] == acct.ChownOperand("anon") {
			chowned[c[2]] = true
		}
	}
	for _, want := range []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".config", "app", "conf.toml"),
		filepath.Join(home, ".config"),        // the seeded dir must be account-owned
		filepath.Join(home, ".config", "app"), // nested seeded dir too
	} {
		if !chowned[want] {
			t.Errorf("seeded path %q was not chowned to %q (calls: %v)", want, acct.ChownOperand("anon"), r.calls)
		}
	}
}

// TestSeedChownDoesNotAssumeAUserPrivateGroup pins the PORTABLE chown operand for
// the seeder, the same rule provision pins for the login-env write.
//
// The seeder used to issue `chown <account>:<account>`, which hard-codes the
// Debian/Ubuntu user-private-group convention. On a host that does not create a
// per-user group - NixOS sets GROUP=100 in /etc/default/useradd, so the account
// lands in the shared `users` group and `getent group anon-x` returns nothing -
// that operand fails with `chown: invalid group`, aborting the seed part-way
// through a tree it has already half-copied. The trailing-colon form `<account>:`
// asks coreutils for the account's OWN login group and is correct on both.
func TestSeedChownDoesNotAssumeAUserPrivateGroup(t *testing.T) {
	tmpl := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(tmpl, ".bashrc"), 0o644, "export FOO=bar\n")
	writeFile(t, filepath.Join(tmpl, ".config", "app", "conf.toml"), 0o600, "key=1\n")

	r := &fakeRunner{}
	if _, err := seedhome.Seed(context.Background(), r, tmpl, home, "anon-work", false); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	var sawChown bool
	for _, c := range r.calls {
		if len(c) < 2 || c[0] != "chown" {
			continue
		}
		sawChown = true
		if c[1] != "anon-work:" {
			t.Errorf("chown operand = %q, want %q (trailing colon, NO group name: the group must be the account's own login group, not an assumed user-private group)", c[1], "anon-work:")
		}
		if strings.Contains(strings.TrimSuffix(c[1], ":"), ":") {
			t.Errorf("chown operand %q names a GROUP; a same-named user-private group does not exist on every distribution", c[1])
		}
	}
	if !sawChown {
		t.Fatalf("seed issued no chown at all; calls: %v", r.calls)
	}
}

// TestSeedStripsSetuidSetgid is the load-bearing security rule: a template file
// carrying setuid/setgid must land WITHOUT those bits (the uid-transition-escape
// closure). This must never regress silently.
func TestSeedStripsSetuidSetgid(t *testing.T) {
	tmpl := t.TempDir()
	home := t.TempDir()
	// 0o6755 = setuid+setgid+rwxr-xr-x.
	writeFile(t, filepath.Join(tmpl, "tool"), os.ModeSetuid|os.ModeSetgid|0o755, "#!/bin/sh\n")

	r := &fakeRunner{}
	if _, err := seedhome.Seed(context.Background(), r, tmpl, home, "anon", false); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	info, err := os.Stat(filepath.Join(home, "tool"))
	if err != nil {
		t.Fatalf("stat seeded tool: %v", err)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Errorf("seeded file kept setuid/setgid/sticky bits: mode %v", info.Mode())
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("seeded file perm = %v, want 0755 (bits below setuid preserved)", info.Mode().Perm())
	}
}

// TestSeedCollisionErrorsWithoutForce: an existing target aborts the seed (writing
// NOTHING) and names every collision, unless --force.
func TestSeedCollisionErrorsWithoutForce(t *testing.T) {
	tmpl := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(tmpl, ".bashrc"), 0o644, "template\n")
	writeFile(t, filepath.Join(tmpl, "fresh"), 0o644, "new\n")
	// The home already has .bashrc (skel would have dropped one).
	writeFile(t, filepath.Join(home, ".bashrc"), 0o644, "existing\n")

	r := &fakeRunner{}
	_, err := seedhome.Seed(context.Background(), r, tmpl, home, "anon", false)
	var ce *seedhome.ErrCollision
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ErrCollision, got %v", err)
	}
	if len(ce.Paths) != 1 || ce.Paths[0] != ".bashrc" {
		t.Errorf("collision paths = %v, want [.bashrc]", ce.Paths)
	}
	// NOTHING was written: the pre-existing file is untouched and the fresh file was
	// NOT created (atomic abort before any copy).
	if got, _ := os.ReadFile(filepath.Join(home, ".bashrc")); string(got) != "existing\n" {
		t.Errorf(".bashrc was modified despite collision: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, "fresh")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fresh file was created despite an aborted seed")
	}
	if len(r.calls) != 0 {
		t.Errorf("no chown should run on an aborted seed, got %v", r.calls)
	}
}

// TestSeedForceOverwrites: --force overwrites the colliding file and records it.
func TestSeedForceOverwrites(t *testing.T) {
	tmpl := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(tmpl, ".bashrc"), 0o644, "template\n")
	writeFile(t, filepath.Join(home, ".bashrc"), 0o644, "existing\n")

	r := &fakeRunner{}
	res, err := seedhome.Seed(context.Background(), r, tmpl, home, "anon", true)
	if err != nil {
		t.Fatalf("Seed --force: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(home, ".bashrc")); string(got) != "template\n" {
		t.Errorf(".bashrc not overwritten: %q", got)
	}
	if len(res.Overwrote) != 1 || res.Overwrote[0] != ".bashrc" {
		t.Errorf("Overwrote = %v, want [.bashrc]", res.Overwrote)
	}
}

// TestSeedRefusesSymlink: a template must be plain files/dirs; a symlink is refused
// (it could point a seeded file at another uid's target or escape the home).
func TestSeedRefusesSymlink(t *testing.T) {
	tmpl := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(tmpl, "real"), 0o644, "x\n")
	if err := os.Symlink("real", filepath.Join(tmpl, "link")); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	r := &fakeRunner{}
	if _, err := seedhome.Seed(context.Background(), r, tmpl, home, "anon", false); err == nil {
		t.Fatalf("expected a symlink refusal, got nil")
	}
}

// TestSeedMissingTemplateErrors: a non-existent template dir is a loud error, not a
// silent no-op.
func TestSeedMissingTemplateErrors(t *testing.T) {
	home := t.TempDir()
	r := &fakeRunner{}
	if _, err := seedhome.Seed(context.Background(), r, filepath.Join(t.TempDir(), "nope"), home, "anon", false); err == nil {
		t.Fatalf("expected an error for a missing template, got nil")
	}
}
