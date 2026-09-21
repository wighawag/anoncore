package provision_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acct "github.com/wighawag/anoncore/account"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/provision"
)

// stubLoginEnv neutralises the real login-env writer for ONE unit test and restores
// it on cleanup. Unit tests drive the fake Runner and never create a real home, so
// the default WriteLoginEnv (which touches the filesystem) would spuriously fail;
// they stub it locally. This is DELIBERATELY per-test rather than a global TestMain
// stub: a global mutation is shared into the integration test binary (both files
// compile into ONE binary under -tags integration), where it silently neutralised
// the REAL writer TestRealProvisionRoundTrip must exercise (the e2e finding, BUG 3).
func stubLoginEnv(t *testing.T) {
	t.Helper()
	old := provision.WriteLoginEnv
	provision.WriteLoginEnv = func(context.Context, provision.Runner, string, string) error { return nil }
	t.Cleanup(func() { provision.WriteLoginEnv = old })
}

// Fake shells for the unit tests: absolute paths in the NixOS shape (a stable
// alias under /run/current-system/sw/bin, NOT an FHS path), so a test that
// asserts the useradd argv cannot accidentally pass by matching a conventional
// string the production code hard-coded.
const (
	fakeLoginShell   = "/run/current-system/sw/bin/bash"
	fakeNologinShell = "/run/current-system/sw/bin/nologin"
)

// stubShells pins shell resolution to a FIXED pair for ONE unit test and restores
// it on cleanup, so the test asserts the argv provisioning builds WITHOUT
// depending on which shells happen to be installed on the machine running the
// tests (the point of making the resolver injectable). It is deliberately
// per-test rather than a global TestMain stub, for the same reason stubLoginEnv
// is: a global mutation leaks into the integration test binary, where the REAL
// resolver must run.
func stubShells(t *testing.T) {
	t.Helper()
	old := provision.Shells
	provision.Shells = provision.ShellResolver{
		Look: func(name string) (string, error) {
			switch name {
			case "bash":
				return fakeLoginShell, nil
			case "nologin":
				return fakeNologinShell, nil
			}
			return "", errors.New("executable file not found in $PATH")
		},
		Stat:       func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		ShellsFile: filepath.Join(t.TempDir(), "no-etc-shells"),
	}
	t.Cleanup(func() { provision.Shells = old })
}

// fakeRunner is the unit-test seam standing in for the real ExecRunner: it
// records every command the provisioning issues and answers the `getent passwd`
// existence probes from a scripted set of already-present accounts, so the whole
// add/rm/list/status wiring is exercised WITHOUT creating a real Unix user
// (mirrors netcage's recordRunner). No useradd/userdel ever hits the box.
type fakeRunner struct {
	calls       [][]string
	present     map[string]bool // accounts getent should report as existing
	sudoAllowed bool            // when true, `sudo -n -l -U` reports the account CAN sudo

	// sudoScript, when set, fully overrides the default `sudo -n -l -U` fixture so a
	// test can drive an EXACT stdout/stderr/exit-code shape (the lenient exit-0
	// no-rights build, a real grant, the not-allowed text, an ambiguous blob) through
	// the same Runner seam - no real sudo. It takes precedence over sudoAllowed.
	sudoScript *sudoResult
}

// sudoResult is a scripted `sudo -l -U` outcome for the fake Runner: the exact
// stdout, stderr and (via exit) error the real sudo would return, so the parse is
// tested against real-shaped fixtures without a real sudo binary.
type sudoResult struct {
	stdout string
	stderr string
	exit   int // 0 => nil error; non-zero => an *exitErr with that code
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	// sudo -n -l -U <account>: the read-only, non-interactive sudo-absence probe. By default report the
	// finding-observed "not allowed" (a freshly-provisioned anon account has no sudo
	// rights); a test can flip sudoAllowed to exercise the positive-detection path,
	// or set sudoScript for an exact stdout/stderr/exit fixture.
	if name == "sudo" {
		if r.sudoScript != nil {
			if r.sudoScript.exit == 0 {
				return r.sudoScript.stdout, r.sudoScript.stderr, nil
			}
			return r.sudoScript.stdout, r.sudoScript.stderr, &exitErr{code: r.sudoScript.exit}
		}
		if r.sudoAllowed {
			return "User anon may run the following commands on host:\n    (ALL : ALL) ALL", "", nil
		}
		return "", "User anon is not allowed to run sudo on host.", &exitErr{code: 1}
	}
	// getent passwd <name>: report presence from the scripted set. A missing entry
	// is getent's exit-2 (an error with empty stdout), same as the real tool.
	if name == "getent" && len(args) >= 2 && args[0] == "passwd" {
		acct := args[1]
		if r.present != nil && r.present[acct] {
			return acct + ":x:30034:30034::/home/" + acct + ":/bin/bash", "", nil
		}
		return "", "", &exitErr{code: 2}
	}
	// useradd/userdel: pretend success, and reflect the mutation in `present` so a
	// re-run sees the account as existing (idempotency is testable).
	if name == "useradd" {
		if r.present == nil {
			r.present = map[string]bool{}
		}
		r.present[args[len(args)-1]] = true
	}
	if name == "userdel" {
		delete(r.present, args[len(args)-1])
	}
	return "", "", nil
}

type exitErr struct{ code int }

func (e *exitErr) Error() string { return "exit status" }
func (e *exitErr) ExitCode() int { return e.code }

func joined(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// add on a fresh box provisions BOTH the anon login account AND a distinct
// dedicated shim service account, via the injected Runner (no real useradd).
func TestAddProvisionsAccountAndShim(t *testing.T) {
	stubLoginEnv(t)
	stubShells(t)
	r := &fakeRunner{}
	res, err := provision.Add(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Add error: %v", err)
	}
	if res.Created != true {
		t.Errorf("Created = %v, want true on a fresh account", res.Created)
	}
	out := joined(r.calls)
	// the login account
	if !strings.Contains(out, "useradd") || !strings.Contains(out, "anon") {
		t.Errorf("expected a useradd for anon, got:\n%s", out)
	}
	// the DISTINCT dedicated shim service account (own UID)
	if !strings.Contains(out, "anon-shim") {
		t.Errorf("expected a distinct shim account anon-shim, got:\n%s", out)
	}
	// the shim must be a --system service account with a nologin shell (it never
	// logs in; it only runs the shim and dials the endpoint).
	if !strings.Contains(out, "--system") || !strings.Contains(out, "nologin") {
		t.Errorf("shim account must be --system + nologin, got:\n%s", out)
	}
}

// add is IDEMPOTENT: re-running it on an already-provisioned account is a clean
// no-op (no second useradd), not an error.
func TestAddIdempotent(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Add(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Add (existing) error: %v", err)
	}
	if res.Created {
		t.Errorf("Created = true, want false: re-add on an existing account is a no-op")
	}
	if strings.Contains(joined(r.calls), "useradd") {
		t.Errorf("re-add must NOT call useradd again, got:\n%s", joined(r.calls))
	}
}

// A named account provisions anon-<name> and its OWN shim anon-<name>-shim.
func TestAddNamed(t *testing.T) {
	stubLoginEnv(t)
	stubShells(t)
	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon-work"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	out := joined(r.calls)
	if !strings.Contains(out, "anon-work-shim") {
		t.Errorf("named account must get its own anon-work-shim, got:\n%s", out)
	}
}

// bare rm removes forcing hooks only (a no-op until the nft/persistence tasks
// land) and NEVER calls userdel: the account's home stays intact.
func TestRmLeavesAccountIntact(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Rm(context.Background(), r, "anon", false /* purgeAccount */)
	if err != nil {
		t.Fatalf("Rm error: %v", err)
	}
	if res.AccountRemoved {
		t.Errorf("AccountRemoved = true on a bare rm, want false")
	}
	if strings.Contains(joined(r.calls), "userdel") {
		t.Errorf("bare rm must NOT call userdel, got:\n%s", joined(r.calls))
	}
}

// rm --purge-account (the explicit opt-in) removes the account AND its shim.
func TestRmPurgeAccount(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Rm(context.Background(), r, "anon", true /* purgeAccount */)
	if err != nil {
		t.Fatalf("Rm --purge-account error: %v", err)
	}
	if !res.AccountRemoved {
		t.Errorf("AccountRemoved = false, want true under --purge-account")
	}
	out := joined(r.calls)
	if !strings.Contains(out, "userdel") || !strings.Contains(out, "anon-shim") {
		t.Errorf("purge must userdel both anon and its shim, got:\n%s", out)
	}
}

// rm --purge-account on an absent account is a clean no-op, not an error.
func TestRmPurgeAbsent(t *testing.T) {
	r := &fakeRunner{}
	res, err := provision.Rm(context.Background(), r, "anon", true)
	if err != nil {
		t.Fatalf("Rm on absent account error: %v", err)
	}
	if res.AccountRemoved {
		t.Errorf("AccountRemoved = true on an absent account, want false")
	}
}

// list enumerates the anon accounts that actually exist on the box (reads the
// account table, NOT a maintained index), and excludes the shim service accounts.
func TestListReadsFromBox(t *testing.T) {
	r := &fakeRunner{}
	accounts, err := provision.List(context.Background(), r, []string{
		"root:x:0:0::/root:/bin/bash",
		"anon:x:30034:30034::/home/anon:/bin/bash",
		"anon-shim:x:995:983::/home/anon-shim:/usr/sbin/nologin",
		"anon-work:x:30035:30035::/home/anon-work:/bin/bash",
		"anon-work-shim:x:996:984::/home/anon-work-shim:/usr/sbin/nologin",
		"alice:x:1000:1000::/home/alice:/bin/bash",
	})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("List = %v, want 2 anon accounts (anon, anon-work), no shims/root/alice", accounts)
	}
	got := map[string]bool{}
	for _, a := range accounts {
		got[a.Account] = true
	}
	if !got["anon"] || !got["anon-work"] {
		t.Errorf("List missing anon/anon-work: %v", accounts)
	}
	if got["anon-shim"] || got["anon-work-shim"] {
		t.Errorf("List must EXCLUDE shim service accounts: %v", accounts)
	}
}

// status --json emits machine-readable state read from the box: the account and
// shim existence, their UIDs, and (later) the marker. It must be valid JSON with
// the account name and both UIDs.
func TestStatusJSONMachineReadable(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.Exists {
		t.Errorf("Exists = false, want true")
	}
	if !st.ShimExists {
		t.Errorf("ShimExists = false, want true")
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("status --json is not valid JSON: %v", err)
	}
	if back["account"] != "anon" {
		t.Errorf("json account = %v, want anon (fields: %v)", back["account"], back)
	}
}

// status on an absent account reports Exists=false, not an error (a queryable
// negative, so a caller/CI can branch on it).
func TestStatusAbsent(t *testing.T) {
	r := &fakeRunner{}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status (absent) error: %v", err)
	}
	if st.Exists {
		t.Errorf("Exists = true on an absent account, want false")
	}
}

// WithMarker on an account WITH a marker reports Forced + the marker record (the
// share-class the status view carries, story 20). The marker Store is pointed at
// a scratch dir, so the real /etc is never read/written.
func TestStatus_WithMarker_ReportsForced(t *testing.T) {
	store := marker.Store{BaseDir: filepath.Join(t.TempDir(), "anonctl")}
	m := marker.New("anon", "30034", endpoint.ClassTorShared, "1.0.0", time.Now())
	if err := store.Write(m); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	st, err = st.WithMarker(store)
	if err != nil {
		t.Fatalf("WithMarker: %v", err)
	}
	if !st.Forced || st.Marker == nil {
		t.Fatalf("a present marker must set Forced+Marker; got Forced=%v Marker=%v", st.Forced, st.Marker)
	}
	if st.Marker.EndpointClass != endpoint.ClassTorShared {
		t.Errorf("status must carry the endpoint share-class; got %q", st.Marker.EndpointClass)
	}
}

// WithMarker on an account with NO marker is a clean "not forced" (Forced=false,
// Marker=nil), never an error, so status/CI can branch on absence.
func TestStatus_WithMarker_MissingIsCleanNotForced(t *testing.T) {
	store := marker.Store{BaseDir: filepath.Join(t.TempDir(), "anonctl")}
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	st, err = st.WithMarker(store)
	if err != nil {
		t.Fatalf("WithMarker (missing) must not error; got %v", err)
	}
	if st.Forced || st.Marker != nil {
		t.Fatalf("a missing marker must be a clean not-forced; got Forced=%v Marker=%v", st.Forced, st.Marker)
	}
	// And it must appear in status --json as forced:false.
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), `"forced":false`) {
		t.Errorf("status --json must report forced:false for a missing marker; got %s", b)
	}
}

// add provisions the login account with NO sudo grant: none of the commands it
// issues add the account to a sudo/wheel group or write a sudoers entry. This is
// the CLOSE-AT-ADD invariant from work/notes/findings/uid-transition-escape-surface.go:
// a socket the anon account could own via `sudo` would carry a DIFFERENT uid and
// escape the `meta skuid` forcing, so `add` must never grant it.
func TestAddGrantsNoSudo(t *testing.T) {
	stubShells(t)
	stubLoginEnv(t)
	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	for _, c := range r.calls {
		line := strings.Join(c, " ")
		// No group grant into sudo/wheel (via useradd --groups or usermod -aG), and no
		// visudo/sudoers write.
		if strings.Contains(line, "sudo") || strings.Contains(line, "wheel") || strings.Contains(line, "visudo") {
			t.Errorf("add must not grant sudo; offending command: %q", line)
		}
		if strings.Contains(line, "usermod") && (strings.Contains(line, "-G") || strings.Contains(line, "-aG") || strings.Contains(line, "--groups")) {
			t.Errorf("add must not add supplementary groups (a sudo/wheel path); offending command: %q", line)
		}
	}
}

// add provisions the login account with a minimal login PATH that omits the sbin
// directories holding setuid network binaries (exim4/pppd/mount.nfs per the
// audit finding), shrinking what the account can even name. The write goes
// through the injectable WriteLoginEnv seam so the unit test asserts the CONTENT
// without touching a real home directory.
func TestAddWritesMinimalLoginPATH(t *testing.T) {
	var gotAccount, gotContent string
	var wrote bool
	old := provision.WriteLoginEnv
	provision.WriteLoginEnv = func(_ context.Context, _ provision.Runner, account, content string) error {
		wrote = true
		gotAccount, gotContent = account, content
		return nil
	}
	t.Cleanup(func() { provision.WriteLoginEnv = old })
	stubShells(t)

	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	if !wrote {
		t.Fatalf("Add must write the account's minimal login PATH via WriteLoginEnv")
	}
	if gotAccount != "anon" {
		t.Errorf("WriteLoginEnv account = %q, want anon", gotAccount)
	}
	if !strings.Contains(gotContent, "PATH="+provision.LoginPATH) {
		t.Errorf("login env must export the minimal PATH %q; got:\n%s", provision.LoginPATH, gotContent)
	}
	// The minimal PATH must NOT expose the sbin dirs that carry the setuid network
	// binaries the audit flagged (exim4/pppd/mount.nfs live under /usr/sbin, /sbin).
	for _, sbin := range []string{"/usr/sbin", "/sbin"} {
		for _, entry := range strings.Split(provision.LoginPATH, ":") {
			if entry == sbin {
				t.Errorf("minimal LoginPATH must not include %q (setuid network binaries live there): %q", sbin, provision.LoginPATH)
			}
		}
	}
}

// re-add on an existing account does NOT rewrite the login env (idempotent: the
// env is written only when the account is freshly created, so a re-run never
// clobbers an operator's edited profile).
func TestAddIdempotentDoesNotRewriteLoginEnv(t *testing.T) {
	var wrote bool
	old := provision.WriteLoginEnv
	provision.WriteLoginEnv = func(_ context.Context, _ provision.Runner, _, _ string) error {
		wrote = true
		return nil
	}
	t.Cleanup(func() { provision.WriteLoginEnv = old })

	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add (existing) error: %v", err)
	}
	if wrote {
		t.Errorf("re-add must NOT rewrite the login env for an already-provisioned account")
	}
}

// status positively reports the account has NO sudo rights: it runs the
// `sudo -l -U <account>` probe through the Runner and reports SudoChecked=true,
// SudoAllowed=false (a positive assertion, not merely an absence). This is the
// PROVE-IN-VERIFY sudo vector surfaced where an operator sees it.
func TestStatusReportsNoSudo(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.SudoChecked {
		t.Errorf("SudoChecked = false, want true (status must probe sudo)")
	}
	if st.SudoAllowed {
		t.Errorf("SudoAllowed = true, want false for a freshly-provisioned anon account")
	}
	// The positive no-sudo assertion must show up in status --json.
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), `"sudoAllowed":false`) {
		t.Errorf("status --json must report sudoAllowed:false; got %s", b)
	}
}

// status DETECTS sudo when it IS present (the probe is a real positive check, not
// a hard-coded false): a box that grants the account sudo is reported
// SudoAllowed=true so an operator is warned the uid-transition vector is open.
func TestStatusDetectsSudoWhenPresent(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}, sudoAllowed: true}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.SudoChecked || !st.SudoAllowed {
		t.Errorf("a box that grants sudo must report SudoChecked=true SudoAllowed=true; got checked=%v allowed=%v", st.SudoChecked, st.SudoAllowed)
	}
}

// status on an ABSENT account does not probe sudo (there is no account to probe):
// SudoChecked stays false so the field is not a misleading "no sudo" for a
// non-existent account.
func TestStatusAbsentDoesNotProbeSudo(t *testing.T) {
	r := &fakeRunner{}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status (absent) error: %v", err)
	}
	if st.SudoChecked {
		t.Errorf("SudoChecked = true on an absent account, want false")
	}
}

// status reads sudo-absence from the OUTPUT, not the exit code alone: on a lenient
// sudo build that prints "not allowed to run sudo" but exits 0 for a no-rights
// account (observed: sudo 1.9.16p2, work/notes/findings/e2e-binary-revalidation-2.md),
// the account must still be read as NO sudo (SudoChecked=true, SudoAllowed=false),
// NOT a false "can sudo" false-alarm.
func TestStatusLenientExitZeroNotAllowedReadsAsNoSudo(t *testing.T) {
	r := &fakeRunner{
		present:    map[string]bool{"anon": true, "anon-shim": true},
		sudoScript: &sudoResult{stdout: "User anon is not allowed to run sudo on host.\n", exit: 0},
	}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.SudoChecked {
		t.Errorf("SudoChecked = false, want true: the not-allowed text is a decisive verdict")
	}
	if st.SudoAllowed {
		t.Errorf("SudoAllowed = true on a lenient exit-0 not-allowed output, want false (must not false-alarm)")
	}
}

// status still CATCHES a genuine grant: a real permitted-commands listing (the
// "may run the following commands" shape) is read as SudoAllowed=true, whatever the
// exit code, so the parse never hides a real sudo escape.
func TestStatusRealGrantReadsAsSudoAllowed(t *testing.T) {
	r := &fakeRunner{
		present: map[string]bool{"anon": true, "anon-shim": true},
		sudoScript: &sudoResult{stdout: "Matching Defaults entries for anon on host:\n    env_reset\n\n" +
			"User anon may run the following commands on host:\n    (ALL : ALL) ALL\n", exit: 0},
	}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.SudoChecked || !st.SudoAllowed {
		t.Errorf("a real permitted-commands listing must report SudoChecked=true SudoAllowed=true; got checked=%v allowed=%v", st.SudoChecked, st.SudoAllowed)
	}
}

// status's sudo-absence probe is STRICTLY NON-INTERACTIVE: it issues
// `sudo -n -l -U <account>`, never a bare `sudo -l -U`. Listing ANOTHER user's sudo
// privileges (`-U <account>`) requires the caller to be authorized, and without
// `-n` that authorization pops a polkit/sudo password prompt on a desktop (the same
// vector the verify sudoVector fix closed). With `-n`, sudo prints "a password is
// required" and returns instead of prompting, so `anonctl status` never pops a
// dialog. This asserts the argv through the Runner seam: no real sudo, no prompt.
func TestStatusSudoProbeIsNonInteractive(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	if _, err := provision.Status(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Status error: %v", err)
	}
	var sudoCall []string
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "sudo" {
			sudoCall = c
			break
		}
	}
	if sudoCall == nil {
		t.Fatalf("status did not issue a sudo probe; calls:\n%s", joined(r.calls))
	}
	want := []string{"sudo", "-n", "-l", "-U", "anon"}
	if strings.Join(sudoCall, " ") != strings.Join(want, " ") {
		t.Errorf("sudo probe argv = %q, want %q (the -n makes it non-interactive so status never prompts)", sudoCall, want)
	}
}

// status maps a `-n`-blocked probe (sudo prints "a password is required" and
// returns non-interactively when auth would be needed) to UNKNOWN => SudoChecked=false:
// an honest not-conclusive verdict, NEVER a false "has sudo" nor a false "no sudo".
// This is the outcome that keeps the report honest once the probe can no longer
// prompt (it fails unattended instead of popping a dialog).
func TestStatusPasswordRequiredReadsAsUnknown(t *testing.T) {
	r := &fakeRunner{
		present:    map[string]bool{"anon": true, "anon-shim": true},
		sudoScript: &sudoResult{stderr: "sudo: a password is required\n", exit: 1},
	}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if st.SudoChecked {
		t.Errorf("SudoChecked = true on a `-n` password-required probe, want false (UNKNOWN: not conclusively checked)")
	}
	if st.SudoAllowed {
		t.Errorf("SudoAllowed = true on a `-n` password-required probe: must never false-alarm")
	}
}

// status surfaces an AMBIGUOUS / unparseable probe result as UNKNOWN (not-checked),
// NEVER as a false "has sudo" (a false alarm) NOR a false "no sudo" (which would
// hide a real escape): output with neither the not-allowed text nor a
// permitted-commands listing is not a verdict. UNKNOWN maps onto SudoChecked=false.
func TestStatusAmbiguousOutputReadsAsUnknown(t *testing.T) {
	cases := map[string]*sudoResult{
		"empty exit0":     {stdout: "", stderr: "", exit: 0},
		"empty exit1":     {stdout: "", stderr: "", exit: 1},
		"unrelated blob":  {stdout: "sudo: a password is required\n", stderr: "", exit: 1},
		"garbled listing": {stdout: "something happened but not a recognisable verdict\n", exit: 0},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}, sudoScript: script}
			st, err := provision.Status(context.Background(), r, "anon")
			if err != nil {
				t.Fatalf("Status error: %v", err)
			}
			// UNKNOWN: no verdict. SudoChecked=false (so SudoAllowed is meaningless and is
			// never read as either a false "has sudo" or a false "no sudo").
			if st.SudoChecked {
				t.Errorf("SudoChecked = true on an ambiguous probe (%s), want false (UNKNOWN)", name)
			}
			if st.SudoAllowed {
				t.Errorf("SudoAllowed = true on an ambiguous probe (%s): must never false-alarm", name)
			}
		})
	}
}

// homeRunner is the seam for exercising the REAL (default) WriteLoginEnv without
// root: `getent passwd` answers with a passwd line whose home field is a temp
// dir, so the writer writes a real file into a scratch home and its chown flows
// through as a recorded call instead of a privileged mutation.
type homeRunner struct {
	home  string
	calls [][]string
}

func (r *homeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == "getent" && len(args) >= 2 && args[0] == "passwd" {
		return args[1] + ":x:30034:100::" + r.home + ":" + fakeLoginShell, "", nil
	}
	return "", "", nil
}

// TestWriteLoginEnvChownDoesNotAssumeAUserPrivateGroup is the regression pin for
// the OBSERVED failure: `anonctl add livetest` aborted on NixOS with
//
//	chown "/home/anon-livetest/.profile" to anon-livetest: exit status 1:
//	chown: invalid group: 'anon-livetest:anon-livetest'
//
// The `<account>:<account>` operand hard-codes the Debian/Ubuntu user-private-group
// convention (USERGROUPS_ENAB yes). NixOS sets GROUP=100 in /etc/default/useradd,
// so the account lands in the shared `users` group and NO per-user group is ever
// created (`getent group anon-livetest` returns nothing) - so the group half of
// the operand names a group that does not exist. The trailing-colon form
// `<account>:` asks coreutils to use "that user's login group", which is the
// per-user group on Debian and `users` on NixOS: one operand, both hosts, no
// group lookup and no distro branch.
//
// It asserts the ARGUMENTS through the Runner seam (a real chown needs root), and
// the account name deliberately differs from any group name a test could match by
// accident.
func TestWriteLoginEnvChownDoesNotAssumeAUserPrivateGroup(t *testing.T) {
	home := t.TempDir()
	r := &homeRunner{home: home}

	if err := provision.WriteLoginEnv(context.Background(), r, "anon-livetest", "export PATH=/bin\n"); err != nil {
		t.Fatalf("WriteLoginEnv: %v", err)
	}

	var chown []string
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "chown" {
			chown = c
			break
		}
	}
	if chown == nil {
		t.Fatalf("WriteLoginEnv issued no chown; calls:\n%s", joined(r.calls))
	}
	want := []string{"chown", acct.ChownOperand("anon-livetest"), filepath.Join(home, ".profile")}
	if strings.Join(chown, " ") != strings.Join(want, " ") {
		t.Errorf("chown argv = %q, want %q", chown, want)
	}
	// The operand must be `<account>:` exactly: a TRAILING COLON and NO group name.
	if chown[1] != "anon-livetest:" {
		t.Errorf("chown operand = %q, want %q (trailing colon, no group name)", chown[1], "anon-livetest:")
	}
	if strings.Contains(strings.TrimSuffix(chown[1], ":"), ":") {
		t.Errorf("chown operand %q names a GROUP explicitly; a same-named user-private group does not exist on every distribution (NixOS puts the account in `users`)", chown[1])
	}
}

// TestAddResolvesShellsAndNeverNamesAnFHSPath pins the second and third bugs: the
// shells written into passwd are RESOLVED on the host, not assumed.
//
// `useradd --shell /bin/bash` only WARNS when the shell is missing and creates the
// account anyway, so on NixOS (no /bin/bash, no /usr/sbin/nologin, no /sbin/nologin,
// no /bin/false) the old code left a login account whose shell does not exist -
// which is what breaks `use`. The assertion is on the argv through the Runner seam:
// the useradd calls must carry exactly what the injected resolver returned.
func TestAddResolvesShellsAndNeverNamesAnFHSPath(t *testing.T) {
	stubLoginEnv(t)
	stubShells(t)
	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add error: %v", err)
	}

	var login, shim []string
	for _, c := range r.calls {
		if len(c) == 0 || c[0] != "useradd" {
			continue
		}
		if strings.Contains(strings.Join(c, " "), "--system") {
			shim = c
			continue
		}
		login = c
	}
	if login == nil || shim == nil {
		t.Fatalf("expected a login and a shim useradd; got:\n%s", joined(r.calls))
	}

	assertShell := func(kind string, argv []string, want string) {
		t.Helper()
		var got string
		for i, a := range argv {
			if a == "--shell" && i+1 < len(argv) {
				got = argv[i+1]
			}
		}
		if got != want {
			t.Errorf("%s useradd --shell = %q, want the RESOLVED %q", kind, got, want)
		}
	}
	assertShell("login", login, fakeLoginShell)
	assertShell("shim", shim, fakeNologinShell)

	// No provisioning command may name a conventional FHS shell path: every one of
	// these is absent on NixOS, and useradd accepts a missing shell with only a
	// warning, so an assumed path is a silently bad passwd entry.
	for _, c := range r.calls {
		line := strings.Join(c, " ")
		for _, assumed := range []string{"/bin/bash", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false"} {
			if strings.Contains(line, " "+assumed) {
				t.Errorf("provisioning must not hard-code the FHS path %q (it does not exist on every distribution); offending command: %q", assumed, line)
			}
		}
	}
}

// TestAddRefusesBeforeCreatingAnythingWhenAShellCannotBeResolved is the
// HALF-PROVISIONED-RESIDUE pin, which is why the observed failure mattered beyond
// its error message: the aborted `anonctl add` left the login account existing,
// no shim, and no forcing installed - a state an operator has to unpick by hand.
//
// So an unresolvable shell must be refused BEFORE the first mutation: no useradd
// at all, and no login env written. Resolution happens up front for BOTH accounts,
// never lazily at each account's creation.
func TestAddRefusesBeforeCreatingAnythingWhenAShellCannotBeResolved(t *testing.T) {
	var wroteEnv bool
	old := provision.WriteLoginEnv
	provision.WriteLoginEnv = func(context.Context, provision.Runner, string, string) error {
		wroteEnv = true
		return nil
	}
	t.Cleanup(func() { provision.WriteLoginEnv = old })

	// A host with a perfectly good login shell but NO resolvable nologin: the lazy
	// order would create the login account first and only then discover the problem.
	oldShells := provision.Shells
	provision.Shells = provision.ShellResolver{
		Look: func(name string) (string, error) {
			if name == "bash" {
				return fakeLoginShell, nil
			}
			return "", errors.New("executable file not found in $PATH")
		},
		Stat:       func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		ShellsFile: filepath.Join(t.TempDir(), "no-etc-shells"),
	}
	t.Cleanup(func() { provision.Shells = oldShells })

	r := &fakeRunner{}
	res, err := provision.Add(context.Background(), r, "anon")
	if err == nil {
		t.Fatalf("Add must fail when a shell cannot be resolved; got %+v", res)
	}
	if !strings.Contains(err.Error(), "nologin") {
		t.Errorf("error %q must name the shell it could not resolve", err)
	}
	if res.Created || res.ShimCreated {
		t.Errorf("Add reported creation on a refused host: %+v", res)
	}
	if strings.Contains(joined(r.calls), "useradd") {
		t.Errorf("a refused Add must create NOTHING (no half-provisioned residue), got:\n%s", joined(r.calls))
	}
	if wroteEnv {
		t.Errorf("a refused Add must not write a login env")
	}
}

// TestAddIdempotentNeedsNoShellResolution keeps re-add a PURE no-op: an
// already-provisioned account is not re-examined against the host's shells, so a
// box that could not provision today still answers `add` cleanly for accounts it
// already has.
func TestAddIdempotentNeedsNoShellResolution(t *testing.T) {
	oldShells := provision.Shells
	provision.Shells = provision.ShellResolver{
		Look:       func(string) (string, error) { return "", errors.New("no shells at all here") },
		Stat:       func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		ShellsFile: filepath.Join(t.TempDir(), "no-etc-shells"),
	}
	t.Cleanup(func() { provision.Shells = oldShells })

	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Add(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("re-add on an existing account must be a clean no-op, got: %v", err)
	}
	if res.Created || res.ShimCreated {
		t.Errorf("re-add reported creation: %+v", res)
	}
}
