package account_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anoncore/account"
)

// Each anon account gets its OWN dedicated shim service account, derived by the
// `-shim` suffix so that name resolution is pure and idempotent: `anon` ->
// `anon-shim` (matching the validated recipe), `anon-<name>` -> `anon-<name>-shim`.
func TestShimAccount(t *testing.T) {
	cases := map[string]string{
		"anon":       "anon-shim",
		"anon-work":  "anon-work-shim",
		"anon-media": "anon-media-shim",
	}
	for acct, want := range cases {
		if got := account.ShimAccount(acct); got != want {
			t.Errorf("ShimAccount(%q) = %q, want %q", acct, got, want)
		}
	}
}

// ResolveAccount maps a user-typed name to the Unix account name: empty/`anon` ->
// the default, any other name -> `anon-<name>`, and an already-prefixed name is
// NOT double-prefixed.
func TestResolveAccount(t *testing.T) {
	cases := map[string]string{
		"":          "anon",
		"anon":      "anon",
		"work":      "anon-work",
		"media":     "anon-media",
		"anon-work": "anon-work",
		"  work  ":  "anon-work",
	}
	for in, want := range cases {
		if got := account.ResolveAccount(in); got != want {
			t.Errorf("ResolveAccount(%q) = %q, want %q", in, got, want)
		}
	}
}

// IsAnonLogin recognises the operator-managed LOGIN accounts (`anon` /
// `anon-<name>`) and rejects the `*-shim` service accounts (implementation, not
// operator-managed) and unrelated system users.
func TestIsAnonLogin(t *testing.T) {
	logins := []string{"anon", "anon-work", "anon-media"}
	for _, name := range logins {
		if !account.IsAnonLogin(name) {
			t.Errorf("IsAnonLogin(%q) = false, want true", name)
		}
	}
	notLogins := []string{"anon-shim", "anon-work-shim", "root", "alice", "anonymous"}
	for _, name := range notLogins {
		if account.IsAnonLogin(name) {
			t.Errorf("IsAnonLogin(%q) = true, want false", name)
		}
	}
}

// TestChownOperandUsesTheTrailingColonForm pins the PORTABLE chown owner operand.
//
// `chown <account>:<account>` assumes a user-private group of the same name, which
// is the Debian/Ubuntu `USERGROUPS_ENAB yes` convention and NOT universal: NixOS
// sets GROUP=100 in /etc/default/useradd, so an anon account lands in the shared
// `users` group with no per-user group at all, and the two-name operand fails with
// `chown: invalid group`. The trailing-colon form asks coreutils for "that user's
// login group", which resolves correctly on BOTH hosts with no lookup, no branch,
// and no distro check.
func TestChownOperandUsesTheTrailingColonForm(t *testing.T) {
	for _, name := range []string{"anon", "anon-work", "anon-livetest", "anon-shim"} {
		got := account.ChownOperand(name)
		if got != name+":" {
			t.Errorf("ChownOperand(%q) = %q, want %q", name, got, name+":")
		}
		// It must name NO group: exactly one colon, at the very end.
		if strings.Count(got, ":") != 1 || !strings.HasSuffix(got, ":") {
			t.Errorf("ChownOperand(%q) = %q, want a single TRAILING colon and no group name", name, got)
		}
	}
}
