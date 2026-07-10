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

import "strings"

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
func ResolveAccount(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == DefaultAccount {
		return DefaultAccount
	}
	if strings.HasPrefix(name, namePrefix) {
		return name
	}
	return namePrefix + name
}

// ShimAccount returns the dedicated shim service-account name for an anon
// account: `anon` -> `anon-shim`, `anon-<name>` -> `anon-<name>-shim`. Each anon
// account gets its OWN shim UID (a separate service account) so that later only
// the shim UID, never the anon UID, may reach the upstream endpoint. The `-shim`
// suffix mirrors the validated manual recipe, which created `anon-shim` for
// `anon`.
func ShimAccount(account string) string { return account + "-shim" }

// IsAnonLogin reports whether a passwd name is an anon LOGIN account (`anon` or
// `anon-<name>`) and NOT one of the `*-shim` service accounts, which are
// implementation, not operator-managed accounts.
func IsAnonLogin(name string) bool {
	if strings.HasSuffix(name, "-shim") {
		return false
	}
	return name == DefaultAccount || strings.HasPrefix(name, DefaultAccount+"-")
}
