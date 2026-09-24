package provision_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/provision"
)

// fakeMarkers is a MarkerReader whose answer per account is fixed by the test:
// present, absent, or UNREADABLE. The unreadable case is the one that matters -
// it is what an unprivileged caller actually gets, and the state the old
// `forced bool` silently rendered as "not forced".
type fakeMarkers struct {
	present map[string]marker.Marker
	err     error
}

func (f fakeMarkers) Read(account string) (marker.Marker, error) {
	if f.err != nil {
		return marker.Marker{}, f.err
	}
	if m, ok := f.present[account]; ok {
		return m, nil
	}
	return marker.Marker{}, marker.ErrNotFound
}

// fakeLedger is a LedgerReader: either a set of managed accounts, or an error (an
// unprivileged caller cannot read the root-only ledger at all).
type fakeLedger struct {
	accounts []string
	err      error
}

func (f fakeLedger) List() ([]accountconfig.Config, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []accountconfig.Config
	for _, a := range f.accounts {
		out = append(out, accountconfig.Config{Account: a})
	}
	return out, nil
}

func passwd() []string {
	return []string{
		"root:x:0:0::/root:/bin/bash",
		"anon:x:8801:8801::/home/anon:/bin/bash",
		"anon-shim:x:412:412::/home/anon-shim:/usr/sbin/nologin",
		"anon-work:x:8802:8802::/home/anon-work:/bin/bash",
		"anon-work-shim:x:413:413::/home/anon-work-shim:/usr/sbin/nologin",
		"alice:x:1000:1000::/home/alice:/bin/bash",
	}
}

func listRows(t *testing.T) []provision.AccountListing {
	t.Helper()
	rows, err := provision.List(context.Background(), &fakeRunner{}, passwd())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return rows
}

func rowFor(t *testing.T, rows []provision.AccountListing, account string) provision.AccountListing {
	t.Helper()
	for _, r := range rows {
		if r.Account == account {
			return r
		}
	}
	t.Fatalf("no row for %q in %v", account, rows)
	return provision.AccountListing{}
}

// THE REGRESSION TEST FOR THE SILENT-VERDICT BUG.
//
// Reproduce the exact live condition: an UNPRIVILEGED caller, for whom
// `/etc/anonctl` is unreadable, listing accounts that ARE forced. Determining the
// answer is impossible here, so the one thing the row must never do is answer
// confidently. It used to: every row carried `"forced": false`.
func TestListCannotClaimUnforcedWhenItCannotRead(t *testing.T) {
	denied := fmt.Errorf("read marker %q: %w", "/etc/anonctl/anon.json", os.ErrPermission)
	rows := provision.Resolve(listRows(t),
		fakeLedger{err: fmt.Errorf("list account configs in %q: %w", "/etc/anonctl/accounts", os.ErrPermission)},
		fakeMarkers{err: denied})

	for _, row := range rows {
		if row.Forcing.State != provision.StateUnknown {
			t.Errorf("%s: forcing state %q for a caller that CANNOT read the marker; want %q",
				row.Account, row.Forcing.State, provision.StateUnknown)
		}
		if row.Forcing.Reason == "" {
			t.Errorf("%s: an unknown forcing state must carry its reason", row.Account)
		}
		if row.Managed != nil {
			t.Errorf("%s: managed = %v for a caller that cannot read the ledger; want null (undetermined)",
				row.Account, *row.Managed)
		}
	}

	// And the JSON a consumer actually parses must not contain a bare `"forced":
	// false` (nor the two sudo bools `list` never probes): an absent key or an
	// explicit unknown is the contract, a zero-valued bool is not.
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{`"forced"`, `"sudoChecked"`, `"sudoAllowed"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("list rows must not emit %s (nothing on the list path computes it):\n%s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), `"state":"unknown"`) {
		t.Errorf("list rows must carry an explicit unknown forcing state:\n%s", raw)
	}
}

// The determined cases: a readable marker store yields a real verdict per account,
// forced and unforced, each positively established.
func TestListDeterminesForcingWhenItCanRead(t *testing.T) {
	m := marker.New("anon", "8801", endpoint.ClassTorShared, "0.6.2", time.Now())
	rows := provision.Resolve(listRows(t),
		fakeLedger{accounts: []string{"anon"}},
		fakeMarkers{present: map[string]marker.Marker{"anon": m}})

	if got := rowFor(t, rows, "anon").Forcing.State; got != provision.StateForced {
		t.Errorf("anon has a marker; forcing state = %q, want %q", got, provision.StateForced)
	}
	if got := rowFor(t, rows, "anon-work").Forcing.State; got != provision.StateUnforced {
		t.Errorf("anon-work has no marker and the store was readable; forcing state = %q, want %q", got, provision.StateUnforced)
	}
	if got := rowFor(t, rows, "anon-work").Forcing.Reason; got != "" {
		t.Errorf("a DETERMINED verdict needs no reason; got %q", got)
	}
}

// A corrupt marker is UNKNOWN, not unforced: failing to parse a claim is not the
// same as establishing there is none.
func TestListReportsACorruptMarkerAsUnknown(t *testing.T) {
	rows := provision.Resolve(listRows(t),
		fakeLedger{accounts: []string{"anon"}},
		fakeMarkers{err: errors.New("invalid marker JSON: unexpected end of JSON input")})
	if got := rowFor(t, rows, "anon").Forcing.State; got != provision.StateUnknown {
		t.Errorf("a corrupt marker must be %q, not %q", provision.StateUnknown, got)
	}
}

// MANAGED-NESS is the field a consumer provisioning from this list actually needs,
// and it is a different question from passwd existence. On a host that DECLARES its
// accounts, every slot exists in passwd from the first converge whether `anonctl
// add` ever touched it or not.
func TestListReportsManagedSeparatelyFromExistence(t *testing.T) {
	rows := provision.Resolve(listRows(t),
		fakeLedger{accounts: []string{"anon"}},
		fakeMarkers{})

	managed := rowFor(t, rows, "anon")
	if !managed.Exists || managed.Managed == nil || !*managed.Managed {
		t.Errorf("anon: want exists=true managed=true; got exists=%v managed=%v", managed.Exists, managed.Managed)
	}
	// The declared-but-never-added slot: it EXISTS (honest box truth) and is NOT
	// managed. A consumer that reads only `exists` would hand it a jailed-looking
	// interface while it has no forcing at all.
	declared := rowFor(t, rows, "anon-work")
	if !declared.Exists {
		t.Errorf("anon-work: passwd existence must stay the existence source")
	}
	if declared.Managed == nil || *declared.Managed {
		t.Errorf("anon-work: want managed=false (a declared slot anonctl never added); got %v", declared.Managed)
	}
}

// The UNION half: an account in the ledger with NO passwd entry is exactly the
// drift `verify`'s identity precondition catches (activation deleted the account
// while anonctl's rules still govern its old uid). `list` is where an operator
// looks, so it appears as a row - exists=false, managed=true - rather than
// silently not appearing at all.
func TestListUnionsInLedgerAccountsWithNoPasswdEntry(t *testing.T) {
	rows := provision.Resolve(listRows(t),
		fakeLedger{accounts: []string{"anon", "anon-ghost"}},
		fakeMarkers{})

	ghost := rowFor(t, rows, "anon-ghost")
	if ghost.Exists {
		t.Errorf("anon-ghost has no passwd entry; exists must be false")
	}
	if ghost.Managed == nil || !*ghost.Managed {
		t.Errorf("anon-ghost is in the ledger; managed must be true, got %v", ghost.Managed)
	}
	if ghost.Shim != "anon-ghost-shim" {
		t.Errorf("a union row must still name its shim; got %q", ghost.Shim)
	}
}

// An UNREADABLE ledger must not produce union rows (we cannot enumerate it), and
// must not report the accounts we CAN see as unmanaged.
func TestAnUnreadableLedgerAddsNoRowsAndClaimsNothing(t *testing.T) {
	rows := provision.Resolve(listRows(t),
		fakeLedger{err: os.ErrPermission},
		fakeMarkers{})
	if len(rows) != 2 {
		t.Fatalf("want exactly the 2 passwd rows when the ledger is unreadable; got %d: %v", len(rows), rows)
	}
	for _, row := range rows {
		if row.Managed != nil {
			t.Errorf("%s: managed=%v from an UNREADABLE ledger; want null", row.Account, *row.Managed)
		}
		if row.ManagedReason == "" {
			t.Errorf("%s: a null managed state must carry its reason", row.Account)
		}
	}
}

// A row that was never Resolved must not read as unforced either: the undetermined
// default is UNKNOWN, so even a caller that forgets to resolve cannot emit a
// verdict nothing computed.
func TestUnresolvedRowsAreUnknownNotUnforced(t *testing.T) {
	for _, row := range listRows(t) {
		if row.Forcing.State != provision.StateUnknown {
			t.Errorf("%s: an unresolved row must be %q, got %q", row.Account, provision.StateUnknown, row.Forcing.State)
		}
		if row.Managed != nil {
			t.Errorf("%s: an unresolved row must have a null managed state", row.Account)
		}
	}
}

// ShimExists is NULL on a ledger-only row, not a zero-value false. The union row is
// built from the ledger alone, so nothing established whether the shim account
// exists - and reporting `false` there would be the same "a bool nothing computed"
// defect this type exists to fix, wrong in exactly the half-pair case `list` is
// meant to surface (activation deleted the login account, its `-shim` survived).
func TestShimExistsIsNullOnALedgerOnlyRow(t *testing.T) {
	rows := provision.Resolve(listRows(t),
		fakeLedger{accounts: []string{"anon", "anon-ghost"}},
		fakeMarkers{})

	ghost := rowFor(t, rows, "anon-ghost")
	if ghost.ShimExists != nil {
		t.Errorf("a ledger-only row establishes nothing about the shim; shimExists must be null, got %v", *ghost.ShimExists)
	}
	// ...while a passwd row DID establish it (whatever the answer was): the
	// distinction being pinned is determined-vs-not, not the value.
	present := rowFor(t, rows, "anon")
	if present.ShimExists == nil {
		t.Error("a passwd row queried the shim account, so shimExists must be determined, not null")
	}

	raw, err := json.Marshal(ghost)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"shimExists":null`) {
		t.Errorf("an undetermined shimExists must serialise as null:\n%s", raw)
	}
}
