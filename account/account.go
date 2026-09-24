// Package account owns the substrate-agnostic account-NAME vocabulary shared by
// every anon* tool: the default account name, the user-name -> Unix-name
// resolution, and the dedicated-shim naming. It is the small piece of shared
// language that provisioning (anoncore/provision) needs and that each tool's own
// command surface (anonctl's internal/cli, anonbox's argv parser) also builds on.
//
// It was extracted DOWN out of anonctl's internal/cli to break a layering
// inversion: internal/provision (core provisioning logic) used cli.ShimAccount /
// cli.DefaultAccount / cli.ResolveAccount, which made a shared core depend on
// anonctl's CLI surface and blocked a clean extraction. The name vocabulary is
// genuinely shared substrate-agnostic core, so it lives here; the argv parsing,
// verb table, and flag grammar stay in each tool. anonctl's internal/cli now
// re-exports these so its callers are unchanged.
//
// The naming is anonctl's published convention (`anon` for the bare account,
// `anon-<name>` for a named one, `<account>-shim` for the dedicated shim service
// account). anonbox uses a different account prefix (`anonbox-<name>`), so a tool
// that needs a different default supplies its own; this package captures the
// default-plus-prefix mechanism and anonctl's concrete `anon` default that
// provisioning was already hard-coding through cli.
package account

import (
	"fmt"
	"strings"
)

// DefaultAccount is the account a BARE verb (no name) targets: anonctl's generic
// "anonymized account" name. It is anonctl's published default (distinct from
// anon-pi's `anonpi` and anonbox's `anonbox`). anonctl OWNS this name.
const DefaultAccount = "anon"

// namePrefix is the prefix a NAMED account gets: `work` becomes `anon-work`. The
// user names the suffix; anonctl owns the prefix.
const namePrefix = DefaultAccount + "-"

// ResolveAccount maps a user-typed name to the actual Unix account name. An empty
// name or the literal `anon` is the default account; any other name `x` becomes
// `anon-x`. A name the user already spelled with anonctl's `anon-` prefix is NOT
// double-prefixed (`anon-work` stays `anon-work`, never `anon-anon-work`).
//
// It VALIDATES the result (ValidateName) and returns an error rather than a
// string, because name resolution is the one chokepoint every verb passes through
// and the downstream substrate cannot represent every name a user might type: see
// ValidateName for why an underscore is a correctness problem and not a style
// preference.
func ResolveAccount(name string) (string, error) {
	resolved := ResolveAccountLegacy(name)
	if err := ValidateName(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// ResolveAccountLegacy is ResolveAccount WITHOUT the name validation: the bare
// name mapping, total and infallible.
//
// It exists for exactly one reason, and the name is meant to discourage every
// other use: an OLDER build of the tool accepted names this one refuses, so a box
// can already have an `anon-a_b` account with forcing installed. Validating on
// EVERY verb would leave that account unreachable - no `status`, and crucially no
// `rm` - which turns a naming bug into an account a tool can no longer tear down.
// So the READ and TEARDOWN verbs resolve through here, and the verbs that INSTALL
// forcing resolve through the strict ResolveAccount. The hard guarantee that no
// COLLIDING ruleset is ever installed does not rest on this choice: the ruleset
// generator refuses an ambiguous name itself, whatever route the caller took.
func ResolveAccountLegacy(name string) string {
	name = strings.TrimSpace(name)
	switch {
	case name == "" || name == DefaultAccount:
		return DefaultAccount
	case strings.HasPrefix(name, namePrefix):
		return name
	default:
		return namePrefix + name
	}
}

// ValidateName accepts only a RESOLVED account name made of lowercase
// alphanumerics and `-`, starting with a letter.
//
// The restriction is a CORRECTNESS one, imposed by the egress substrate rather
// than by taste. anonctl derives a per-account nftables table name from the
// account (`anonctl_<account>`), and nft identifiers cannot contain `-`, so the
// dashes become underscores. That mapping is only injective if the account name
// has no underscores of its own: `anon-a_b` and `anon-a-b` both render
// `anonctl_anon_a_b`. Two accounts sharing one table is not a cosmetic clash -
// the second `add` SILENTLY REPLACES the first account's forcing (the ruleset is
// loaded as an atomic table replace), and every later question put to the kernel
// about one account is answered about the other. The only safe moment to refuse
// that is before anything is provisioned, so it is refused HERE, at resolution.
//
// Uppercase is refused for the same family of reasons one level down: Unix
// account names are conventionally lowercase (useradd's own NAME_REGEX), and a
// case-only difference between two accounts is an ambiguity nothing downstream
// benefits from carrying.
func ValidateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("empty account name")
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("account name %q has leading or trailing whitespace", name)
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return fmt.Errorf("invalid account name %q: it must start with a lowercase letter", name)
			}
		case r == '-':
			if i == 0 {
				return fmt.Errorf("invalid account name %q: it must start with a lowercase letter", name)
			}
		case r == '_':
			return fmt.Errorf("invalid account name %q: an underscore is not allowed because anonctl names each account's "+
				"nftables table `anonctl_<account>` with `-` rewritten to `_` (nft identifiers cannot contain `-`), so %q and "+
				"its all-dashes twin would SHARE one table and one account's forcing would silently replace the other's. "+
				"Use lowercase letters, digits and `-` only", name, name)
		default:
			return fmt.Errorf("invalid account name %q: %q is not allowed. An account name must be lowercase letters, "+
				"digits and `-` only, starting with a letter, because anonctl derives its per-account nftables table name "+
				"(`anonctl_<account>`) from it and that derivation must be unambiguous", name, string(r))
		}
	}
	if strings.HasSuffix(name, "-") {
		return fmt.Errorf("invalid account name %q: it must not end with `-`", name)
	}
	return nil
}

// ShimAccount returns the dedicated shim service-account name for an anon
// account: `anon` -> `anon-shim`, `anon-<name>` -> `anon-<name>-shim`. Each anon
// account gets its OWN shim UID (a separate service account) so that later only
// the shim UID, never the anon UID, may reach the upstream endpoint. The `-shim`
// suffix mirrors the validated manual recipe, which created `anon-shim` for
// `anon`.
func ShimAccount(account string) string { return account + "-shim" }

// ChownOperand returns the `chown` OWNER operand that hands a path to an account
// AND to that account's own login group, whatever that group happens to be:
// `<account>:` - the account name followed by a TRAILING COLON and no group name.
//
// The colon is load-bearing and the missing group name is the whole point. Per
// coreutils, "if a colon but no group name follows the user name, that user is
// made the owner of the files and the group of the files is changed to that
// user's login group", so the GROUP is whatever the host actually gave the
// account. The obvious-looking `<account>:<account>` form instead HARD-CODES the
// Debian/Ubuntu user-private-group convention (`USERGROUPS_ENAB yes`, where
// useradd creates a per-user group of the same name). That convention is not
// universal: NixOS sets `GROUP=100` in /etc/default/useradd, so useradd puts the
// account in the shared `users` group and creates NO per-user group, and
// `chown anon-x:anon-x` fails with `chown: invalid group`. One operand form is
// correct on both, with no group lookup and no distro check.
func ChownOperand(account string) string { return account + ":" }

// IsAnonLogin reports whether a passwd name is an anon LOGIN account (`anon` or
// `anon-<name>`) and NOT one of the `*-shim` service accounts, which are
// implementation, not operator-managed accounts.
func IsAnonLogin(name string) bool {
	if strings.HasSuffix(name, "-shim") {
		return false
	}
	return name == DefaultAccount || strings.HasPrefix(name, DefaultAccount+"-")
}
