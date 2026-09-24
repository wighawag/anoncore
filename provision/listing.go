package provision

import (
	"errors"
	"fmt"
	"sort"

	acct "github.com/wighawag/anoncore/account"
	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/marker"
)

// ForcingState is `list`'s TRI-STATE answer to "is this account forced?". It
// exists because the two-valued answer was a lie: the row used to carry a plain
// `forced bool` that NOTHING on the list path ever computed, so every row of
// `anonctl list --json` reported `"forced": false` at every privilege level -
// including for accounts that were, in fact, forced. The failure was silent and in
// the UNSAFE direction (an account that IS jailed reads as not jailed), and a
// consumer had no way to tell a determination from a zero value.
//
// A tri-state makes the undetermined case UNREPRESENTABLE as "no": a consumer
// switching on State must handle Unknown explicitly, and the compiler-free
// equivalent (a JSON consumer) sees a string it does not recognise rather than a
// confident `false`. It is the same discipline AccountStatus.SudoChecked already
// applies to the sudo probe, applied where it was missing.
type ForcingState string

const (
	// StateForced: a marker was READ for this account. It is a CLAIM that `verify`
	// passed at some point, not a live proof that the rules are loaded right now -
	// that is what `anonctl probe` answers.
	StateForced ForcingState = "forced"
	// StateUnforced: the marker's ABSENCE was positively established (the directory
	// was readable and held no marker for this account). A clean, determined "no".
	StateUnforced ForcingState = "unforced"
	// StateUnknown: the answer could NOT be determined - typically an unprivileged
	// caller who cannot read the marker, or a corrupt marker. It is never a "no".
	StateUnknown ForcingState = "unknown"
)

// Forcing is the tri-state forcing verdict plus, when the answer is Unknown, the
// REASON it could not be determined (the underlying error, e.g. "permission
// denied"), so an operator can act on it instead of guessing. Reason is
// diagnostic text, not a contract: switch on State.
type Forcing struct {
	State  ForcingState `json:"state"`
	Reason string       `json:"reason,omitempty"`
}

// AccountListing is ONE ROW of `list`. It is deliberately a DIFFERENT type from
// AccountStatus rather than a reuse of it: AccountStatus carries fields (Forced,
// SudoChecked, SudoAllowed, Marker) that `status` computes per-account and `list`
// does not, and sharing the struct is exactly how `list` came to emit three
// verdicts it never determined. A row here carries only what the list path
// actually establishes.
//
// The passwd table remains the EXISTENCE source (honest box truth), and
// managed-ness is read separately from anonctl's ledger, because on a host that
// DECLARES its accounts (NixOS with `users.mutableUsers = false`) every slot
// exists in passwd from the first converge whether anonctl has ever touched it or
// not. Existence and management are different questions and are answered
// separately.
type AccountListing struct {
	// Account / Shim are the login account and its dedicated shim service account.
	Account string `json:"account"`
	Shim    string `json:"shim"`
	// Exists is PASSWD existence: there is a login entry for this account on the box.
	// It is false for a row that came from the ledger alone (see Resolve): an account
	// anonctl records as managed but that has no passwd entry, which is the drift
	// `verify`'s identity precondition fails on and the condition an operator most
	// wants `list` to show.
	Exists bool `json:"exists"`
	// ShimExists is whether the dedicated shim service account has a passwd entry -
	// or NULL when that was not established, which is the case for a ledger-only row
	// (there was no passwd enumeration to answer it from). It is a pointer for the
	// same reason Managed is: a plain bool here would be a zero-value `false` that
	// nothing computed, which is exactly the defect this type exists to fix, and it
	// would be WRONG in a case `list` is meant to surface - a half-pair where
	// activation deleted the login account and its `-shim` survived.
	ShimExists *bool  `json:"shimExists"`
	UID        string `json:"uid,omitempty"`
	ShimUID    string `json:"shimUid,omitempty"`

	// Managed is TRUE when anonctl has a ledger record for the account (it added or
	// adopted it and installed forcing), FALSE when the ledger was readable and had
	// none, and NULL when the ledger could not be read at all (an unprivileged
	// caller: the ledger is root-only 0700 by design). Null is a THIRD value on
	// purpose - a consumer that provisions from this list must not read "could not
	// tell" as "not managed", because that hands a jailed-looking interface to an
	// unjailed account.
	Managed *bool `json:"managed"`
	// ManagedReason explains a NULL Managed (the read error). Diagnostic, not a
	// contract.
	ManagedReason string `json:"managedReason,omitempty"`

	// Forcing is the tri-state marker verdict for this account. It is a CLAIM
	// ("verify passed at some point"), never a live proof; `anonctl probe` is the
	// cheap live question.
	Forcing Forcing `json:"forcing"`
}

// MarkerReader is the narrow seam Resolve needs from the marker store (read one
// account's marker). marker.Store satisfies it; a test can substitute a reader
// that returns a permission error without needing an unreadable directory.
type MarkerReader interface {
	Read(account string) (marker.Marker, error)
}

// LedgerReader is the narrow seam Resolve needs from anonctl's ledger (enumerate
// the accounts anonctl MANAGES). accountconfig.Store satisfies it.
type LedgerReader interface {
	List() ([]accountconfig.Config, error)
}

// undetermined is the forcing verdict a freshly-enumerated row carries before
// anything has looked at a marker. It is UNKNOWN, never a zero-value false: a row
// that has not been Resolved must not be able to claim an account is unforced.
func undetermined() Forcing {
	return Forcing{
		State:  StateUnknown,
		Reason: "forcing state not determined (the listing was not resolved against a marker store)",
	}
}

// Resolve fills in each row's managed-ness and forcing state, and UNIONS IN the
// accounts that exist in the ledger but have NO passwd entry.
//
// It returns NO ERROR, and that is the design: an unreadable ledger or marker is a
// STATE of the answer (Managed=nil, Forcing=unknown, each with its reason), not a
// failure of the listing. Returning an error here would push callers back towards
// either failing the whole verb or - far worse, and what the bug was - substituting
// a zero value for a determination they never made.
//
// The ledger-only rows are the drift `verify`'s identity precondition catches:
// anonctl still has a record (and still has rules loaded governing a uid) for an
// account the box no longer has. `list` is where an operator would look for that,
// so it appears here as a row with exists=false and managed=true rather than
// silently not appearing at all.
func Resolve(rows []AccountListing, ledger LedgerReader, markers MarkerReader) []AccountListing {
	managed, managedErr := managedSet(ledger)

	out := make([]AccountListing, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		seen[row.Account] = true
		out = append(out, resolveRow(row, managed, managedErr, markers))
	}

	// The UNION half: an account anonctl records but the box does not have.
	if managedErr == nil {
		var orphans []string
		for name := range managed {
			if !seen[name] {
				orphans = append(orphans, name)
			}
		}
		sort.Strings(orphans)
		for _, name := range orphans {
			out = append(out, resolveRow(AccountListing{
				Account: name,
				Shim:    acct.ShimAccount(name),
				Exists:  false,
			}, managed, managedErr, markers))
		}
	}
	return out
}

// resolveRow decides one row's managed-ness and forcing state.
func resolveRow(row AccountListing, managed map[string]bool, managedErr error, markers MarkerReader) AccountListing {
	if managedErr != nil {
		row.Managed = nil
		row.ManagedReason = managedErr.Error()
	} else {
		v := managed[row.Account]
		row.Managed = &v
	}
	row.Forcing = forcingFor(row.Account, markers)
	return row
}

// forcingFor classifies one account's marker read into the tri-state. The three
// branches are the whole point: a present marker is FORCED, a
// positively-established absence is UNFORCED, and anything else (permission
// denied, a corrupt marker, an I/O error) is UNKNOWN WITH ITS REASON - never a
// silent "no".
func forcingFor(accountName string, markers MarkerReader) Forcing {
	if markers == nil {
		return undetermined()
	}
	_, err := markers.Read(accountName)
	switch {
	case err == nil:
		return Forcing{State: StateForced}
	case errors.Is(err, marker.ErrNotFound):
		return Forcing{State: StateUnforced}
	default:
		return Forcing{State: StateUnknown, Reason: err.Error()}
	}
}

// managedSet reads the ledger into a name set. A read failure is returned as an
// error the caller turns into a NULL managed-ness plus its reason, rather than
// into an empty set (which would report every account as unmanaged).
func managedSet(ledger LedgerReader) (map[string]bool, error) {
	if ledger == nil {
		return nil, fmt.Errorf("managed state not determined (no ledger reader given)")
	}
	configs, err := ledger.List()
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(configs))
	for _, c := range configs {
		set[c.Account] = true
	}
	return set, nil
}
