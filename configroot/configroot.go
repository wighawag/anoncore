// Package configroot owns the SHARED config root (`/etc/anonctl`) and, above all,
// its MODE. It exists because three different stores write under that one
// directory - the credential-free world-readable markers (anoncore/marker), the
// root-only ledger (anoncore/accountconfig), and anonctl's own private shim/rules
// dirs (anonctl internal/systemd) - and each of them used to create the shared
// parent as a SIDE EFFECT of `os.MkdirAll` on its OWN subdirectory.
//
// That is a real defect, not a tidiness point, because `os.MkdirAll` has two
// behaviours that combine badly here:
//
//  1. it creates MISSING PARENTS with the SAME mode as the leaf, so
//     `MkdirAll("/etc/anonctl/accounts", 0700)` creates `/etc/anonctl` itself 0700; and
//  2. it does NOTHING AT ALL to a directory that already exists, so the marker
//     store's later `MkdirAll("/etc/anonctl", 0755)` is a silent no-op.
//
// Since `anonctl add` writes the ledger BEFORE its inline verify writes the
// marker, the ledger won that race on every box, and `/etc/anonctl` was 0700
// root:root in production. The marker's documented contract - "a dependency-free
// signal any UID can read, with no anonctl binary needed" - was therefore FALSE in
// practice: an unprivileged consumer got EACCES on the marker it is supposed to be
// able to read. Whichever store happens to touch the parent first should never
// decide the mode of a directory it does not own.
//
// So the mode is owned HERE, in one place, and asserted EXPLICITLY at write time
// (an `os.Chmod` after the `MkdirAll`) rather than passed as a hint to a call that
// may ignore it. The explicit chmod is also what REPAIRS an existing box: a host
// that already has a 0700 `/etc/anonctl` from an older build is corrected by the
// next write, with no migration step for the operator to run.
//
// Ensuring the root is world-TRAVERSABLE deliberately exposes the NAMES of the
// accounts that have markers (`ls /etc/anonctl` lists `<account>.json`). That is
// intended: the marker is credential-free by construction, and a local account
// name is already visible to any local user in `/etc/passwd`. It must NOT widen
// anything else, which is why EnsureUnder asserts the CHILD's own (private) mode
// in the same call.
package configroot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDir is the real shared config root: `/etc/anonctl`. It is the one
// directory this package owns the mode of. Tests point the stores at a scratch
// dir, which becomes the root for that test (the shared-write isolation
// discipline).
const DefaultDir = "/etc/anonctl"

// Mode is the config root's directory mode: 0755, world-READABLE and
// world-TRAVERSABLE. It is load-bearing for the marker contract: a consumer that
// is not root must be able to traverse `/etc/anonctl` to `stat`/read
// `<account>.json`. It is the mode of the ROOT ONLY; every child asserts its own
// (see EnsureUnder), so a traversable root never implies a readable child.
const Mode os.FileMode = 0o755

// Ensure creates the config root if needed and ASSERTS Mode on it, whether it
// just created it or found it already there. Both halves matter: MkdirAll's mode
// argument is masked by the umask, and it is ignored entirely for an existing
// directory (including one another store created as a missing parent at its own
// private 0700). The explicit chmod is therefore the only thing that actually
// guarantees the documented mode - and the only thing that repairs a box
// provisioned by an older build.
func Ensure(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("configroot: empty config root")
	}
	if err := os.MkdirAll(dir, Mode); err != nil {
		return fmt.Errorf("create config root %q: %w", dir, err)
	}
	if err := os.Chmod(dir, Mode); err != nil {
		return fmt.Errorf("chmod config root %q to %#o: %w", dir, Mode, err)
	}
	return nil
}

// EnsureUnder creates a CHILD directory under the config root at the child's OWN
// mode, ensuring the root FIRST so the child's MkdirAll can never be the thing
// that creates the shared parent (and therefore can never decide its mode).
//
// The child's mode is asserted explicitly too, for the mirror-image reason: a
// 0700 ledger directory that already exists must STAY 0700 even though its parent
// is now traversable. Widening the root must widen nothing inside it, and this is
// where that is enforced rather than assumed.
//
// An EMPTY root means "this store is not rooted in a config root" (a test store
// pointed straight at a scratch directory whose parent is a shared location like
// `/tmp`): the child is still created and its mode asserted, but NO ancestor is
// touched. Ancestors are only ever modified when the caller NAMES the root, so
// this can never chmod a directory the caller did not mean to hand over.
func EnsureUnder(root, child string, childMode os.FileMode) error {
	if strings.TrimSpace(child) == "" {
		return fmt.Errorf("configroot: empty child directory")
	}
	if strings.TrimSpace(root) != "" {
		if !within(root, child) {
			return fmt.Errorf("configroot: %q is not inside the config root %q", child, root)
		}
		if err := Ensure(root); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(child, childMode); err != nil {
		return fmt.Errorf("create dir %q: %w", child, err)
	}
	if err := os.Chmod(child, childMode); err != nil {
		return fmt.Errorf("chmod dir %q to %#o: %w", child, childMode, err)
	}
	return nil
}

// RootFor resolves the config root a store should manage, given the store's OWN
// configured directory and the directory the store uses BY DEFAULT.
//
// The rule is deliberately conservative: the root is managed only when the store
// is at its DEFAULT location (production), or when the caller named the root
// explicitly. A store repointed at a scratch directory gets an EMPTY root, so a
// test can never make anoncore chmod the scratch directory's PARENT - which, for
// a `t.TempDir()`, would be a shared system location.
//
// explicitRoot wins when set (that is how a test exercises the REAL production
// layout: root = scratch, child = scratch/accounts).
func RootFor(explicitRoot, dir, defaultDir string) string {
	if r := strings.TrimSpace(explicitRoot); r != "" {
		return r
	}
	if d := strings.TrimSpace(dir); d == "" || filepath.Clean(d) == filepath.Clean(defaultDir) {
		return DefaultDir
	}
	return ""
}

// within reports whether child is root itself or lives underneath it, so
// EnsureUnder can refuse a caller that names a root the child is not actually in
// (which would otherwise chmod an unrelated directory).
func within(root, child string) bool {
	root = filepath.Clean(root)
	child = filepath.Clean(child)
	if root == child {
		return true
	}
	rel, err := filepath.Rel(root, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
