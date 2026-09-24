// Package provision owns the account + dedicated-shim-UID lifecycle behind the
// four verbs (add/rm/list/status). Every system-mutating call goes through the
// Runner seam (mirroring netcage's jail.ExecRunner) so the whole thing is
// unit-testable against a fake WITHOUT creating a real Unix user: the default
// `go test ./...` run touches no real account state. Only the `integration`-
// tagged test wires the real ExecRunner and asserts it cleans up after itself.
//
// The account layout mirrors the validated manual recipe
// (work/notes/findings/manual-per-uid-tor-recipe.md): a login account (`anon` /
// `anon-<name>`, a normal --create-home shell user whose egress is later forced)
// and, alongside it, a DISTINCT dedicated shim service account (`<account>-shim`,
// a --system nologin user) that runs the shim and is the ONLY UID later allowed
// to dial the upstream endpoint. This task provisions those accounts; it installs
// NO egress forcing (that is the nftables/persistence tasks).
package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	acct "github.com/wighawag/anoncore/account"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/sudoprobe"
)

// Runner abstracts command execution so provisioning is unit-testable without a
// real useradd/userdel/getent (the integration test uses the real one). It
// mirrors netcage's jail.Runner: a single Run that returns stdout, stderr, and
// the raw exec error so callers can classify an exit code. anonctl runs its
// mutations as root (the ufw stance), so the real runner shells out privileged.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// AddResult reports what add did. Created is false when the account already
// existed (the idempotent no-op path), true when this call provisioned it.
type AddResult struct {
	Account     string `json:"account"`
	Shim        string `json:"shim"`
	Created     bool   `json:"created"`
	ShimCreated bool   `json:"shimCreated"`
}

// RmResult reports what rm did. AccountRemoved is true only when the explicit
// opt-in deleted the account; a bare rm leaves it false (the home stays intact).
type RmResult struct {
	Account        string `json:"account"`
	Shim           string `json:"shim"`
	AccountRemoved bool   `json:"accountRemoved"`
	ShimRemoved    bool   `json:"shimRemoved"`
}

// AccountStatus is the machine-readable state of one anon account, read from the
// box (the account table), NOT a maintained index. It is the shape `status
// --json` emits. Forcing/marker state is added by the nftables/verify tasks; the
// JSON field names are the durable contract they extend.
type AccountStatus struct {
	Account    string `json:"account"`
	Shim       string `json:"shim"`
	Exists     bool   `json:"exists"`
	ShimExists bool   `json:"shimExists"`
	UID        string `json:"uid,omitempty"`
	ShimUID    string `json:"shimUid,omitempty"`

	// SudoChecked reports whether the sudo-absence probe produced a DECISIVE verdict
	// for this account. It is false in two cases: the account does not exist (not
	// probed at all), and the probe ran but its `sudo -l -U` output was ambiguous /
	// unparseable (UNKNOWN: we do not guess). SudoAllowed is meaningful only when
	// SudoChecked is true; a false here means "no reliable sudo verdict", never a
	// silent "no sudo". `status` renders the UNKNOWN case as an explicit line.
	SudoChecked bool `json:"sudoChecked"`
	// SudoAllowed is the POSITIVE result of the `sudo -l -U <account>` probe: false
	// means the account has no sudo rights (the hardened, expected state), true means
	// the box grants it sudo (a UID-transition escape: a sudo'd socket carries a
	// different uid and bypasses the `meta skuid` forcing). This surfaces the
	// CLOSE-AT-ADD invariant as a checkable fact, not just an absence.
	SudoAllowed bool `json:"sudoAllowed"`

	// Forced reports whether the account has a marker (`/etc/anonctl/<account>.json`):
	// anonctl's own convenience view of the SAME dependency-free truth a sibling tool
	// reads directly. The marker FILE is authoritative; this field is a reader of it.
	//
	// It is a POINTER because there are three answers, not two: a marker was read
	// (true), its absence was positively established (false), and the read FAILED so
	// nothing was established (nil). The third is the common case for an unprivileged
	// caller, and it must not serialise as `false`.
	Forced *bool `json:"forced"`
	// Forcing is the same verdict as a tri-state with a REASON, so a consumer that
	// finds `forced: null` can see why. It is the identical shape `list` emits, on
	// purpose: the two verbs answer the same question and must not disagree about how
	// they say "undetermined".
	Forcing Forcing `json:"forcing"`
	// Marker is the account's marker record when present, else nil. It carries the
	// endpoint SHARE-CLASS (story 20) but no endpoint URL/creds.
	Marker *marker.Marker `json:"marker,omitempty"`
}

// WithMarker returns a copy of the status with its marker fields populated from
// the given Store: forced when a marker is present, a clean not-forced when its
// absence was established (marker.ErrNotFound), and UNDETERMINED (Forced=nil,
// Forcing.State=unknown with the reason) when the read failed.
//
// It returns NO ERROR, and that is the fix for a real asymmetry. It used to return
// the read error, and `anonctl status --json` turned that into a non-zero exit with
// NO DOCUMENT AT ALL - so the verb carrying the most detail was the one a consumer
// could get no partial truth from, and the single most common cause was simply
// running without privilege. Worse, it was inconsistent with this verb's own
// treatment of the LEDGER, where an unreadable record has always been a named state
// (`record-unreadable`) precisely so it is never collapsed into "absent". An
// unreadable marker is a STATE of the answer, exactly as it is for `list`, not a
// reason to refuse to report the eight other things that WERE established.
//
// This is the READER side of the marker precedence: `status` reports the same file
// a sibling tool reads directly; it is a convenience view, not a second source of
// truth. Kept separate from Status so the account-table read stays free of any /etc
// dependency (and its unit tests need no marker Store).
func (s AccountStatus) WithMarker(store marker.Store) AccountStatus {
	no, yes := false, true
	m, err := store.Read(s.Account)
	switch {
	case err == nil:
		s.Forced = &yes
		s.Marker = &m
		s.Forcing = Forcing{State: StateForced}
	case errors.Is(err, marker.ErrNotFound):
		s.Forced = &no
		s.Marker = nil
		s.Forcing = Forcing{State: StateUnforced}
	default:
		s.Forced = nil
		s.Marker = nil
		s.Forcing = Forcing{State: StateUnknown, Reason: err.Error()}
	}
	return s
}

// LoginPATH is the minimal login PATH `add` provisions for the anon account. It
// deliberately OMITS the sbin directories (`/usr/local/sbin`, `/usr/sbin`,
// `/sbin`) that carry the setuid network binaries the audit flagged (exim4,
// pppd, mount.nfs live under /usr/sbin and /sbin): a socket one of those opens
// carries a DIFFERENT uid and escapes the `meta skuid` forcing. Shrinking the
// PATH does not REMOVE those binaries (they are system-wide, still reachable by
// absolute path), so this is a partial CLOSE-AT-ADD hardening, not a barrier; the
// residual is documented in the README threat model. See
// work/notes/findings/uid-transition-escape-surface.md.
const LoginPATH = "/usr/local/bin:/usr/bin:/bin"

// WriteLoginEnv writes the account's minimal login environment (its PATH) into a
// shell profile drop-in in the account's home. It is a package-level seam (not a
// hard call) so the unit tests inject a fake that captures the CONTENT without
// touching a real home directory, mirroring the Runner-seam discipline for the
// rest of provisioning. The default implementation writes the real profile via
// the Runner-discovered home; it is replaced only in tests.
var WriteLoginEnv = writeLoginEnv

// Add provisions the anon login account and its distinct dedicated shim service
// account, idempotently. Provisioning each account is a no-op if it already
// exists, so re-running add is a clean no-op (AddResult.Created reports which
// path was taken). Every mutation goes through the Runner, so the unit tests
// never create a real user.
//
// Both accounts' shells are RESOLVED UP FRONT, before the first mutation. That
// ordering is load-bearing, not tidiness: resolving the shim's nologin shell
// lazily (at shim-creation time) means a host that cannot name one gets the login
// account created and then the failure, leaving the HALF-PROVISIONED residue an
// operator has to clean up by hand - a login account that exists, no shim, and no
// forcing installed. Refusing first keeps the failure fail-closed in the only
// sense that matters: nothing was changed. (It mirrors anonctl's
// systemd.PreflightUnitBinaries, which refuses an unresolvable unit binary before
// `add` touches the box.)
func Add(ctx context.Context, r Runner, account string) (AddResult, error) {
	shim := acct.ShimAccount(account)
	res := AddResult{Account: account, Shim: shim}

	loginExists, _, err := accountEntry(ctx, r, account)
	if err != nil {
		return res, err
	}
	shimExists, _, err := accountEntry(ctx, r, shim)
	if err != nil {
		return res, err
	}

	// Resolve the shells ONLY when something actually needs creating, so a fully
	// idempotent re-add stays a pure no-op that issues no lookups at all.
	var shells ResolvedShells
	if !loginExists || !shimExists {
		if shells, err = Shells.Resolve(); err != nil {
			return res, err
		}
	}

	if !loginExists {
		if err := createLoginAccount(ctx, r, account, shells.Login); err != nil {
			return res, err
		}
		res.Created = true
	}
	if !shimExists {
		if err := createShimAccount(ctx, r, shim, shells.Nologin); err != nil {
			return res, err
		}
		res.ShimCreated = true
	}
	return res, nil
}

// Rm removes the account's forcing hooks and, ONLY under the explicit
// purgeAccount opt-in, deletes the login account + its shim (and their homes). A
// bare rm (purgeAccount=false) is the safe default: it never calls userdel, so a
// user's home is never silently deleted. Removing forcing hooks is a no-op until
// the nft/persistence tasks land; the safety gate on account deletion is the
// load-bearing behaviour delivered here.
func Rm(ctx context.Context, r Runner, account string, purgeAccount bool) (RmResult, error) {
	shim := acct.ShimAccount(account)
	res := RmResult{Account: account, Shim: shim}

	// Forcing-hook teardown is a no-op until the nft/persistence tasks exist. It is
	// intentionally a distinct step so a later task fills it without touching the
	// account-deletion gate.

	if !purgeAccount {
		return res, nil
	}

	removed, err := removeAccount(ctx, r, account)
	if err != nil {
		return res, err
	}
	res.AccountRemoved = removed

	shimRemoved, err := removeAccount(ctx, r, shim)
	if err != nil {
		return res, err
	}
	res.ShimRemoved = shimRemoved
	return res, nil
}

// List enumerates the anon LOGIN accounts that actually exist on the box. It
// reads the account table (passwd lines) rather than a maintained index, so it
// reflects ground truth. The shim service accounts (`*-shim`) are excluded: they
// are implementation, not accounts an operator manages. passwdLines is injected
// so the enumeration is pure and testable; the CLI shell reads the real table.
//
// It returns AccountListing rows, NOT AccountStatus, and the rows it returns are
// deliberately UNDETERMINED about forcing (Forcing.State == unknown, Managed ==
// nil) because this function looks at nothing but passwd. Establishing those needs
// the marker store and the ledger, which is Resolve's job; the two are separate so
// that this half stays pure of any `/etc` dependency AND so that no code path can
// emit a confident verdict that nothing computed. That is precisely what the old
// signature allowed: it returned AccountStatus, whose `forced`/`sudoChecked`/
// `sudoAllowed` bools this function never touched, and every row of `anonctl list
// --json` therefore reported a zero-value "false" as though it were an answer.
func List(ctx context.Context, r Runner, passwdLines []string) ([]AccountListing, error) {
	var out []AccountListing
	for _, line := range passwdLines {
		name, uid, ok := parsePasswd(line)
		if !ok || !isAnonLogin(name) {
			continue
		}
		shim := acct.ShimAccount(name)
		shimExists, shimUID, err := accountEntry(ctx, r, shim)
		if err != nil {
			return nil, err
		}
		// Bind a per-iteration copy: ShimExists is a pointer (null == not established),
		// and every row must own its own bool rather than alias a loop variable.
		shimPresent := shimExists
		out = append(out, AccountListing{
			Account:    name,
			Shim:       shim,
			Exists:     true,
			UID:        uid,
			ShimExists: &shimPresent,
			ShimUID:    shimUID,
			Forcing:    undetermined(),
		})
	}
	return out, nil
}

// Status returns the machine-readable state of one account, read from the box. An
// absent account is a queryable negative (Exists=false), not an error, so a
// caller/CI can branch on it.
func Status(ctx context.Context, r Runner, account string) (AccountStatus, error) {
	shim := acct.ShimAccount(account)
	st := AccountStatus{Account: account, Shim: shim}

	exists, uid, err := accountEntry(ctx, r, account)
	if err != nil {
		return st, err
	}
	st.Exists = exists
	st.UID = uid

	shimExists, shimUID, err := accountEntry(ctx, r, shim)
	if err != nil {
		return st, err
	}
	st.ShimExists = shimExists
	st.ShimUID = shimUID

	// Positively probe the sudo-absence invariant, but ONLY for an existing account
	// (probing a non-existent account would be a meaningless "no sudo"). This surfaces
	// the CLOSE-AT-ADD no-sudo hardening as a checkable fact an operator sees in
	// `status`, not just an absence at add-time. An AMBIGUOUS probe (sudoUnknown)
	// leaves SudoChecked=false: it is UNKNOWN, not a verdict, so it never reads as a
	// false "has sudo" (a false alarm) NOR a false "no sudo" (which would hide a real
	// escape). See sudoRights for the parse and how UNKNOWN maps onto the pair.
	if exists {
		switch sudoRights(ctx, r, account) {
		case sudoprobe.Denied:
			st.SudoChecked = true
			st.SudoAllowed = false
		case sudoprobe.Granted:
			st.SudoChecked = true
			st.SudoAllowed = true
		case sudoprobe.Unknown:
			// Leave SudoChecked=false: no reliable verdict. The `status` shell renders
			// this as an explicit UNKNOWN line (see main.go runStatus).
		}
	}
	return st, nil
}

// sudoRights probes whether the account has ANY sudo rights via
// `sudo -n -l -U <account>` (list the account's permitted sudo commands) and
// decides from the OUTPUT, not the exit code. It reads stdout+stderr (the negative
// is commonly on stderr, the listing on stdout) and classifies via the SHARED
// sudoprobe.ParseOutput (the SAME parse verify's sudoVector uses, not a
// duplicate). This is the PROVE side of the sudo vector, robust to lenient sudo
// builds that exit 0 for a no-rights account.
//
// The `-n` (non-interactive) is LOAD-BEARING and mirrors verify's sudoListCommand:
// listing ANOTHER user's sudo privileges (`-U <account>`) requires the CALLER to be
// authorized, and on a desktop that authorization pops a polkit/sudo password
// prompt BEFORE any output (the v0.1.3/v0.1.4 GNOME popup). With `-n`, sudo NEVER
// prompts: when auth would be needed it prints "a password is required" and returns
// non-interactively, which sudoprobe.ParseOutput reads as the honest Unknown (=>
// SudoChecked=false, not conclusively checked), never a false grant/denial. So
// `anonctl status` (and add's sudo-absence surfacing) can never trigger a dialog.
func sudoRights(ctx context.Context, r Runner, account string) sudoprobe.Verdict {
	stdout, stderr, _ := r.Run(ctx, "sudo", "-n", "-l", "-U", account)
	return sudoprobe.ParseOutput(stdout + "\n" + stderr)
}

// createLoginAccount creates the login account (the caller has already checked it
// is absent). It is a normal --create-home shell user: the operator logs into it
// and its egress is forced by a later task. loginShell is the RESOLVED absolute
// path to its interactive shell, never a conventional guess (see shell.go).
func createLoginAccount(ctx context.Context, r Runner, account, loginShell string) error {
	// The login account is created with NO --groups: it is never added to sudo/wheel,
	// so it has no sudo path (the CLOSE-AT-ADD no-sudo invariant). A sudo'd socket
	// would carry a different uid and escape the `meta skuid` forcing.
	if _, stderr, err := r.Run(ctx, "useradd", "--create-home", "--shell", loginShell, account); err != nil {
		return fmt.Errorf("create login account %q: %w: %s", account, err, stderr)
	}
	// Write the account's minimal login PATH (omitting the sbin setuid-network dirs)
	// only on FRESH creation, so a re-run never clobbers an operator's edited
	// profile. Failing to write the env is a real provisioning error (the hardening
	// did not take effect), surfaced to the caller.
	if err := WriteLoginEnv(ctx, r, account, loginEnvContent()); err != nil {
		return fmt.Errorf("write login env for %q: %w", account, err)
	}
	return nil
}

// createShimAccount creates the dedicated shim service account (the caller has
// already checked it is absent). It is a --system, --no-create-home, nologin
// user: it never logs in, it only runs the shim and (later) is the ONLY UID
// allowed to dial the endpoint. nologinShell is the RESOLVED absolute path to a
// login-refusing shell, never a conventional guess (see shell.go).
func createShimAccount(ctx context.Context, r Runner, shim, nologinShell string) error {
	if _, stderr, err := r.Run(ctx, "useradd", "--system", "--no-create-home", "--shell", nologinShell, shim); err != nil {
		return fmt.Errorf("create shim account %q: %w: %s", shim, err, stderr)
	}
	return nil
}

// removeAccount deletes an account and its home if present (idempotent: an absent
// account is a clean no-op, not an error). Returns whether it removed anything.
func removeAccount(ctx context.Context, r Runner, account string) (bool, error) {
	exists, _, err := accountEntry(ctx, r, account)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if _, stderr, err := r.Run(ctx, "userdel", "--remove", account); err != nil {
		return false, fmt.Errorf("remove account %q: %w: %s", account, err, stderr)
	}
	return true, nil
}

// loginEnvContent renders the shell profile drop-in that pins the account's
// minimal login PATH. It is a small, self-contained POSIX-sh snippet exporting
// LoginPATH; a login shell reads it (see writeLoginEnv). Kept a pure function so
// the content is asserted in a unit test without any file I/O.
func loginEnvContent() string {
	return "# Managed by anonctl: minimal login PATH for the anon account.\n" +
		"# Omits the sbin dirs carrying setuid network binaries so the account\n" +
		"# cannot gratuitously name a uid-transition escape. See the anonctl README\n" +
		"# threat model. Edit at your own risk.\n" +
		"export PATH=" + LoginPATH + "\n"
}

// homeMode / envFileMode are the intended modes for the created home-scoped env
// file: owned by the account, readable by it. 0644 mirrors a skel .profile.
const envFileMode = 0o644

// writeLoginEnv is the DEFAULT WriteLoginEnv: it writes the minimal-PATH profile
// drop-in into the account's home as `.profile`, then chowns it to the account so
// the login shell (running as the account) reads it. The chown uses the
// trailing-colon operand (acct.ChownOperand), which gives the file to the
// account's OWN login group instead of assuming a same-named user-private group
// exists - the assumption that aborted `add` on NixOS mid-provision. It discovers the home from
// the passwd entry through the Runner (the same seam the rest of provisioning
// uses to read account state). Any real error (no home, write failure) is
// returned so a failed hardening is not silently swallowed. The unit tests
// replace the WriteLoginEnv seam entirely, so this real writer runs only on a
// live host (exercised by the integration test).
func writeLoginEnv(ctx context.Context, r Runner, account, content string) error {
	home, err := accountHome(ctx, r, account)
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".profile")
	if err := os.WriteFile(path, []byte(content), envFileMode); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	// WriteFile respects umask; re-assert the intended mode, then hand the file to
	// the account so its own login shell can read it.
	if err := os.Chmod(path, envFileMode); err != nil {
		return fmt.Errorf("chmod %q: %w", path, err)
	}
	if _, stderr, err := r.Run(ctx, "chown", acct.ChownOperand(account), path); err != nil {
		return fmt.Errorf("chown %q to %s: %w: %s", path, account, err, stderr)
	}
	return nil
}

// AccountHome returns the account's home directory from its passwd entry through
// the Runner (the same seam the rest of provisioning uses to read account state).
// It is the exported entry point the `seed-home` wiring uses to locate where to
// copy a template; it errors if the account has no resolvable home.
func AccountHome(ctx context.Context, r Runner, account string) (string, error) {
	return accountHome(ctx, r, account)
}

// accountHome returns the account's home directory from its passwd entry (field
// 6). It errors if the account has no resolvable home, so writeLoginEnv never
// writes to a wrong/empty path.
func accountHome(ctx context.Context, r Runner, account string) (string, error) {
	stdout, _, _ := r.Run(ctx, "getent", "passwd", account)
	fields := strings.Split(strings.TrimSpace(stdout), ":")
	if len(fields) < 6 || fields[5] == "" {
		return "", fmt.Errorf("account %q has no home directory in passwd", account)
	}
	return fields[5], nil
}

// accountEntry probes whether an account exists via `getent passwd <name>` and,
// if so, returns its numeric UID. getent exits non-zero (with empty stdout) when
// the account is absent, which we treat as "does not exist", NOT an error, so the
// existence probe is a clean boolean.
func accountEntry(ctx context.Context, r Runner, account string) (exists bool, uid string, err error) {
	stdout, _, runErr := r.Run(ctx, "getent", "passwd", account)
	if runErr != nil {
		// getent's exit 2 == not found. Any getent line means present; empty stdout
		// with an error means absent.
		if strings.TrimSpace(stdout) == "" {
			return false, "", nil
		}
	}
	name, uid, ok := parsePasswd(stdout)
	if !ok || name != account {
		return false, "", nil
	}
	return true, uid, nil
}

// parsePasswd extracts the account name and numeric UID from a passwd line
// (`name:x:uid:gid:gecos:home:shell`). It returns ok=false for a blank or
// malformed line.
func parsePasswd(line string) (name, uid string, ok bool) {
	fields := strings.Split(strings.TrimSpace(line), ":")
	if len(fields) < 3 || fields[0] == "" {
		return "", "", false
	}
	return fields[0], fields[2], true
}

// isAnonLogin reports whether a passwd name is an anon LOGIN account (`anon` or
// `anon-<name>`) and NOT one of the `*-shim` service accounts, which are
// implementation, not operator-managed accounts.
func isAnonLogin(name string) bool {
	return acct.IsAnonLogin(name)
}
