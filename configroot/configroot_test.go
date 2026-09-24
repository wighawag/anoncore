package configroot_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/configroot"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
)

// mode returns a path's permission bits, failing the test if it cannot be
// stat'ed at all (an assertion about a mode is meaningless if the path is gone).
func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return fi.Mode().Perm()
}

// assertRealEtcUntouched is the shared-write isolation discipline: every test in
// this package points its stores at a scratch dir, and must leave the REAL
// `/etc/anonctl` exactly as it found it. It captures the real path's state before
// the body runs and re-checks it after, so a store that silently fell back to its
// production default is caught here rather than on someone's box.
func assertRealEtcUntouched(t *testing.T) {
	t.Helper()
	before, beforeErr := os.Stat(configroot.DefaultDir)
	t.Cleanup(func() {
		after, afterErr := os.Stat(configroot.DefaultDir)
		switch {
		case beforeErr != nil && afterErr == nil:
			t.Fatalf("a test created the REAL %s; tests must only write scratch dirs", configroot.DefaultDir)
		case beforeErr == nil && afterErr != nil:
			t.Fatalf("a test removed the REAL %s: %v", configroot.DefaultDir, afterErr)
		case beforeErr == nil && afterErr == nil && before.Mode() != after.Mode():
			t.Fatalf("a test changed the mode of the REAL %s: %v -> %v", configroot.DefaultDir, before.Mode(), after.Mode())
		}
	})
}

// THE REGRESSION TEST FOR THE LIVE BUG.
//
// `anonctl add` writes the LEDGER (0700 dir) and only later, after its inline
// verify passes, writes the MARKER (documented world-readable). In that order,
// the ledger's `MkdirAll("<root>/accounts", 0700)` creates the SHARED ROOT as a
// missing parent at 0700, and the marker's own `MkdirAll(root, 0755)` is then a
// silent no-op because the directory already exists. The result measured on a
// live box: `/etc/anonctl` 0700 root:root, and an unprivileged consumer getting
// EACCES on the marker it is documented to be able to read with no anonctl binary.
//
// So the order here is the POINT, not incidental: ledger first, marker second.
func TestLedgerWrittenFirstDoesNotLockOutTheMarker(t *testing.T) {
	assertRealEtcUntouched(t)

	root := filepath.Join(t.TempDir(), "anonctl")
	// The REAL production layout: the ledger is a 0700 subdirectory of the root, the
	// markers are files IN the root.
	ledger := accountconfig.Store{RootDir: root, BaseDir: filepath.Join(root, "accounts")}
	markers := marker.Store{BaseDir: root}

	// 1. The ledger goes down first (this is what `add` does).
	if err := ledger.Write(accountconfig.Config{
		Account:       "anon",
		AnonUID:       8801,
		ShimUID:       412,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
	}); err != nil {
		t.Fatalf("ledger write: %v", err)
	}

	// 2. The marker goes down second (this is what the inline verify does).
	m := marker.New("anon", "8801", endpoint.ClassTorShared, "0.6.2", time.Now())
	if err := markers.Write(m); err != nil {
		t.Fatalf("marker write: %v", err)
	}

	// The marker directory must be world-traversable, or the marker is not the
	// dependency-free signal it is documented to be.
	if got := mode(t, root); got != configroot.Mode {
		t.Errorf("marker dir %q is mode %#o after a ledger-first write; want %#o.\n"+
			"This is the live bug: the ledger's MkdirAll created the shared root at its OWN private mode, "+
			"and the marker store's later MkdirAll(root, 0755) did nothing because the dir already existed. "+
			"An unprivileged consumer cannot traverse into it, so the credential-free marker is unreadable.",
			root, got, configroot.Mode)
	}
	markerPath := filepath.Join(root, "anon.json")
	if got := mode(t, markerPath); got != 0o644 {
		t.Errorf("marker file %q is mode %#o; want 0644 (world-readable by design)", markerPath, got)
	}
}

// The mirror-image assertion, and the reason the fix is not simply "chmod 0755 the
// root": making the shared parent traversable must widen NOTHING inside it. The
// ledger holds endpoint addresses and stays root-only, whichever order the two
// stores write in.
func TestWideningTheRootDoesNotWidenTheLedger(t *testing.T) {
	assertRealEtcUntouched(t)

	for _, tc := range []struct {
		name        string
		markerFirst bool
	}{
		{name: "ledger first (the add order)", markerFirst: false},
		{name: "marker first (the reverse order)", markerFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "anonctl")
			ledgerDir := filepath.Join(root, "accounts")
			ledger := accountconfig.Store{RootDir: root, BaseDir: ledgerDir}
			markers := marker.Store{BaseDir: root}

			writeMarker := func() {
				if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.6.2", time.Now())); err != nil {
					t.Fatalf("marker write: %v", err)
				}
			}
			writeLedger := func() {
				if err := ledger.Write(accountconfig.Config{
					Account: "anon", AnonUID: 8801, ShimUID: 412,
					EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
				}); err != nil {
					t.Fatalf("ledger write: %v", err)
				}
			}
			if tc.markerFirst {
				writeMarker()
				writeLedger()
			} else {
				writeLedger()
				writeMarker()
			}

			if got := mode(t, root); got != configroot.Mode {
				t.Errorf("config root %q: mode %#o, want %#o (world-traversable)", root, got, configroot.Mode)
			}
			if got := mode(t, ledgerDir); got != 0o700 {
				t.Errorf("ledger dir %q: mode %#o, want 0700 (root-only: it holds endpoint addresses)", ledgerDir, got)
			}
			if got := mode(t, filepath.Join(ledgerDir, "anon.json")); got != 0o600 {
				t.Errorf("ledger record: mode %#o, want 0600", got)
			}
		})
	}
}

// Ensure REPAIRS a root an older build left 0700, rather than only getting a fresh
// box right. This is what fixes the live hosts: the next write corrects the mode,
// with no migration step for the operator.
func TestEnsureRepairsAnAlreadyTooTightRoot(t *testing.T) {
	assertRealEtcUntouched(t)

	root := filepath.Join(t.TempDir(), "anonctl")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("seed a 0700 root: %v", err)
	}
	if got := mode(t, root); got != 0o700 {
		t.Fatalf("precondition: seeded root should be 0700, got %#o", got)
	}
	if err := configroot.Ensure(root); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := mode(t, root); got != configroot.Mode {
		t.Errorf("Ensure left an existing too-tight root at %#o; want %#o (it must REPAIR, not only create)", got, configroot.Mode)
	}
}

// EnsureUnder asserts the CHILD's mode too, so a subdirectory an older build (or a
// stray umask) left group/other-readable is tightened back rather than trusted.
func TestEnsureUnderTightensAnAlreadyTooWideChild(t *testing.T) {
	assertRealEtcUntouched(t)

	root := filepath.Join(t.TempDir(), "anonctl")
	child := filepath.Join(root, "accounts")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatalf("seed a 0755 child: %v", err)
	}
	if err := configroot.EnsureUnder(root, child, 0o700); err != nil {
		t.Fatalf("EnsureUnder: %v", err)
	}
	if got := mode(t, child); got != 0o700 {
		t.Errorf("EnsureUnder left a too-wide child at %#o; want 0700", got)
	}
}

// An EMPTY root means "no config root": the child is created and its mode asserted,
// but no ancestor is touched. This is the guard that keeps a test store pointed at
// a scratch dir from ever chmod'ing that dir's parent (for a t.TempDir(), a shared
// system location).
func TestEnsureUnderWithNoRootTouchesNoAncestor(t *testing.T) {
	assertRealEtcUntouched(t)

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	child := filepath.Join(parent, "records")
	if err := configroot.EnsureUnder("", child, 0o700); err != nil {
		t.Fatalf("EnsureUnder: %v", err)
	}
	if got := mode(t, parent); got != 0o700 {
		t.Errorf("EnsureUnder with no root changed its child's PARENT to %#o; it must touch no ancestor", got)
	}
	if got := mode(t, child); got != 0o700 {
		t.Errorf("child mode %#o, want 0700", got)
	}
}

// EnsureUnder refuses a root the child is not actually inside, so a mis-wired
// caller cannot chmod an unrelated directory.
func TestEnsureUnderRefusesAChildOutsideTheRoot(t *testing.T) {
	assertRealEtcUntouched(t)

	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "elsewhere", "records")
	if err := configroot.EnsureUnder(root, outside, 0o700); err == nil {
		t.Fatalf("EnsureUnder must refuse a child outside the named root; it accepted %q under %q", outside, root)
	}
	if _, err := os.Stat(root); err == nil {
		t.Errorf("a refused EnsureUnder must create nothing; it created %q", root)
	}
}

// RootFor is the conservative resolution rule: manage the real root in production
// (default or empty dir), manage an explicitly-named root, and manage NOTHING for a
// store repointed at a scratch dir.
func TestRootForOnlyManagesTheRootItIsGiven(t *testing.T) {
	cases := []struct {
		name         string
		explicit     string
		dir          string
		defaultDir   string
		wantRootPath string
	}{
		{"empty dir is production", "", "", "/etc/anonctl/accounts", configroot.DefaultDir},
		{"default dir is production", "", "/etc/anonctl/accounts", "/etc/anonctl/accounts", configroot.DefaultDir},
		{"scratch dir has no root", "", "/tmp/scratch123/accounts", "/etc/anonctl/accounts", ""},
		{"explicit root wins", "/tmp/scratch123", "/tmp/scratch123/accounts", "/etc/anonctl/accounts", "/tmp/scratch123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := configroot.RootFor(tc.explicit, tc.dir, tc.defaultDir); got != tc.wantRootPath {
				t.Errorf("RootFor(%q, %q, %q) = %q; want %q", tc.explicit, tc.dir, tc.defaultDir, got, tc.wantRootPath)
			}
		})
	}
}
