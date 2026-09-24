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
		got, err := account.ResolveAccount(in)
		if err != nil {
			t.Errorf("ResolveAccount(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ResolveAccount(%q) = %q, want %q", in, got, want)
		}
	}
}

// Resolution REFUSES a name the egress substrate cannot name unambiguously. The
// decisive pair is `a_b` vs `a-b`: anonctl rewrites `-` to `_` to build the nft
// table name, so both would land on `anonctl_anon_a_b` and the second account's
// `add` would silently replace the first's forcing. Refused at resolution, before
// anything is provisioned.
func TestResolveAccountRefusesANameThatIsNotNftInjective(t *testing.T) {
	bad := []string{
		"a_b",        // the colliding twin of a-b
		"anon-a_b",   // the same, already prefixed
		"Work",       // uppercase
		"work!",      // punctuation
		"work space", // an interior space
		"work-",      // trailing dash
		"work.d",     // a dot
		"work/../x",  // a path separator
	}
	for _, in := range bad {
		got, err := account.ResolveAccount(in)
		if err == nil {
			t.Errorf("ResolveAccount(%q) = %q with no error; it must REFUSE a name that is not nft-injective", in, got)
			continue
		}
		if got != "" {
			t.Errorf("ResolveAccount(%q) returned a name %q alongside its error; a refusal must yield no usable name", in, got)
		}
	}
}

// The refusal must NAME ITS REASON. An operator told only "invalid name" will
// assume anonctl is being fussy; the message has to say that the nft table name is
// derived from the account and that two names would share one table.
func TestUnderscoreRefusalNamesTheNftReason(t *testing.T) {
	_, err := account.ResolveAccount("a_b")
	if err == nil {
		t.Fatal("expected a refusal for an underscore name")
	}
	msg := err.Error()
	for _, want := range []string{"nftables", "anonctl_<account>", "table"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the underscore refusal must explain the nft table-name collision; %q is missing from:\n%s", want, msg)
		}
	}
}

// ValidateName accepts the names anonctl actually provisions.
func TestValidateNameAcceptsRealAccounts(t *testing.T) {
	for _, name := range []string{"anon", "anon-work", "anon-work-2", "anon-a1", "anon-work-shim"} {
		if err := account.ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v; want accepted", name, err)
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

// ResolveAccountLegacy is the deliberate escape hatch for the READ and TEARDOWN
// path: it performs the same mapping with NO validation, so an account an older
// build created under a now-refused name stays reachable. The hard guarantee (no
// colliding ruleset is ever installed) lives in the ruleset generator, not here.
func TestResolveAccountLegacySkipsValidation(t *testing.T) {
	if got := account.ResolveAccountLegacy("a_b"); got != "anon-a_b" {
		t.Errorf("ResolveAccountLegacy(a_b) = %q, want anon-a_b (it must not validate)", got)
	}
	// It maps identically to the strict form for every name the strict form accepts.
	for _, in := range []string{"", "anon", "work", "anon-work", "  work  "} {
		strict, err := account.ResolveAccount(in)
		if err != nil {
			t.Fatalf("ResolveAccount(%q): %v", in, err)
		}
		if got := account.ResolveAccountLegacy(in); got != strict {
			t.Errorf("the two resolvers disagree on %q: strict %q, legacy %q", in, strict, got)
		}
	}
}
