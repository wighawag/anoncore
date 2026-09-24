//go:build integration
// +build integration

package provision_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	acct "github.com/wighawag/anoncore/account"
	"github.com/wighawag/anoncore/provision"
)

// TestRealProvisionRoundTrip is the ONE test that touches real account state: it
// runs the actual ExecRunner (real useradd/userdel/getent), so it is guarded
// behind the `integration` build tag and is NOT part of the default
// `go test ./...` run. It provisions a throwaway account, asserts idempotency,
// and ALWAYS cleans up the account (and its shim) it created, so it leaves no
// residue on the box. It requires root; it skips (not fails) when not root, so
// an ordinary developer's `go test -tags integration ./...` still passes.
//
// The account name is deliberately an unlikely `anon-anonctlitest` so it cannot
// collide with a real operator account.
func TestRealProvisionRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration provisioning requires root (useradd/userdel); skipping")
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("useradd not available; skipping")
	}

	ctx := context.Background()
	r := provision.ExecRunner{}
	account, err := acct.ResolveAccount("anonctlitest")
	if err != nil {
		t.Fatalf("resolve account: %v", err)
	}
	shim := acct.ShimAccount(account)

	// Guarantee cleanup even if an assertion below fails: always purge the account
	// and shim this test made, and verify they are gone (the "asserts it cleans up
	// the account it made" acceptance requirement).
	defer func() {
		if _, err := provision.Rm(ctx, r, account, true /* purgeAccount */); err != nil {
			t.Errorf("cleanup Rm: %v", err)
		}
		for _, a := range []string{account, shim} {
			if present(ctx, r, a) {
				t.Errorf("cleanup left %q behind", a)
			}
		}
	}()

	// Fresh provision: creates the account and its distinct shim UID.
	res, err := provision.Add(ctx, r, account)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !res.Created {
		t.Fatalf("Add.Created = false on a fresh account")
	}
	if !present(ctx, r, account) {
		t.Fatalf("login account %q was not created", account)
	}
	if !present(ctx, r, shim) {
		t.Fatalf("shim account %q was not created", shim)
	}

	// The shim UID must DIFFER from the login UID (a distinct dedicated service
	// account, story 12).
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.UID == "" || st.ShimUID == "" || st.UID == st.ShimUID {
		t.Errorf("expected distinct UIDs, got login=%q shim=%q", st.UID, st.ShimUID)
	}

	// The freshly-provisioned account must have NO sudo rights (the CLOSE-AT-ADD
	// no-sudo invariant) and status must POSITIVELY report it.
	if !st.SudoChecked {
		t.Errorf("status must probe sudo for an existing account")
	}
	if st.SudoAllowed {
		t.Errorf("a freshly-provisioned account must have no sudo rights; status reported SudoAllowed=true")
	}

	// The minimal login PATH must have been written to the account's home and be
	// owned by the account (the real writeLoginEnv path).
	home := passwdHome(ctx, r, account)
	if home == "" {
		t.Fatalf("could not resolve home for %q", account)
	}
	profile := filepath.Join(home, ".profile")
	data, rerr := os.ReadFile(profile)
	if rerr != nil {
		t.Fatalf("read %q: %v", profile, rerr)
	}
	if !strings.Contains(string(data), "PATH="+provision.LoginPATH) {
		t.Errorf("%q must pin the minimal login PATH %q; got:\n%s", profile, provision.LoginPATH, data)
	}

	// The shell written into each account's passwd entry must REALLY EXIST on this
	// host. This is the assertion no unit test can make (the unit tests assert the
	// argv against a fake), and it is the one that would have caught the FHS
	// assumption on a non-Debian box: `useradd --shell /bin/bash` only WARNS when the
	// shell is missing, so the account is created with a login shell that is not
	// there and `use` breaks later, far from the cause.
	for _, a := range []string{account, shim} {
		shell := passwdShell(ctx, r, a)
		if shell == "" {
			t.Errorf("account %q has no shell in its passwd entry", a)
			continue
		}
		if !filepath.IsAbs(shell) {
			t.Errorf("account %q has a non-absolute login shell %q", a, shell)
		}
		if st, serr := os.Stat(shell); serr != nil {
			t.Errorf("account %q was provisioned with a shell that does not exist: %q (%v)", a, shell, serr)
		} else if st.IsDir() {
			t.Errorf("account %q was provisioned with a DIRECTORY as its shell: %q", a, shell)
		}
	}

	// The login-env drop-in must be owned by the account, whatever GROUP this host
	// gave it (a per-user group on Debian, the shared `users` group on NixOS). The
	// write above already went through the real chown, so reaching here at all means
	// the portable trailing-colon operand was accepted by the host's chown.
	if st, serr := os.Stat(profile); serr != nil {
		t.Errorf("stat %q: %v", profile, serr)
	} else if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if got := strconv.FormatUint(uint64(sys.Uid), 10); got != stAfterWrite(ctx, r, account) {
			t.Errorf("%q is owned by uid %s, want the account's uid %s", profile, got, stAfterWrite(ctx, r, account))
		}
	}

	// Idempotent re-add: a clean no-op, not an error, and no second account.
	res2, err := provision.Add(ctx, r, account)
	if err != nil {
		t.Fatalf("re-Add: %v", err)
	}
	if res2.Created {
		t.Errorf("re-Add.Created = true, want false (idempotent)")
	}
}

// passwdShell returns the account's login shell from its passwd entry (field 7).
func passwdShell(ctx context.Context, r provision.Runner, account string) string {
	out, _, _ := r.Run(ctx, "getent", "passwd", account)
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 {
		return ""
	}
	return fields[6]
}

// stAfterWrite returns the account's numeric uid from the box, for the ownership
// assertion above.
func stAfterWrite(ctx context.Context, r provision.Runner, account string) string {
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		return ""
	}
	return st.UID
}

// passwdHome returns the account's home directory from its passwd entry.
func passwdHome(ctx context.Context, r provision.Runner, account string) string {
	out, _, _ := r.Run(ctx, "getent", "passwd", account)
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 6 {
		return ""
	}
	return fields[5]
}

func present(ctx context.Context, r provision.Runner, account string) bool {
	out, _, _ := r.Run(ctx, "getent", "passwd", account)
	return strings.HasPrefix(strings.TrimSpace(out), account+":")
}
