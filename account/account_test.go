package account_test

import (
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
