package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPairingCodeIsOneUseAndHashed(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	code, exp, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	if exp <= now.UnixMilli() {
		t.Fatal("code should expire in the future")
	}
	inst, cred, err := s.RedeemCode(code, "Bot", "0.1.2-swarm+26.2", "hive", []string{"pause"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if inst.ID == 0 || len(cred) < 10 || inst.CredentialHash == cred {
		t.Fatalf("bad install/credential: %+v %q", inst, cred)
	}
	if _, _, err := s.RedeemCode(code, "Bot", "b", "", nil, now); err != ErrUsed {
		t.Fatalf("second redeem err=%v", err)
	}
}

func TestStateSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	now := time.Now()
	if _, _, err := s.CreateSession("u1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNow(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(s2.State().Sessions) != 1 {
		t.Fatal("session lost")
	}
}

func TestCorruptStateIsRefused(t *testing.T) {
	for _, content := range []string{"{", "", "null", "[]", `{"users":5}`, `{"sessions":{}} trailing`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir); err == nil {
			t.Fatalf("expected corrupt state error for %q", content)
		}
		b, err := os.ReadFile(filepath.Join(dir, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != content {
			t.Fatalf("corrupt state was overwritten: %q", b)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ABCD-EFGH", "ABCDEFGH", true},
		{"abcd efgh", "ABCDEFGH", true},
		{"  abcd-efgh  ", "ABCDEFGH", true},
		{"0I1-23456", "OLL23456", true},
		{"ABCD-EFG", "", false},
		{"ABCD-EFGHJ", "", false},
		{"ABCD-EFG!", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeCode(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("NormalizeCode(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRandomTokenAndHash(t *testing.T) {
	a, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 43 || a == b {
		t.Fatalf("bad tokens %q %q", a, b)
	}
	if _, err := RandomToken(0); err == nil {
		t.Fatal("expected error for empty token size")
	}
	if h := HashToken("x"); len(h) != 64 || h != HashToken("x") || h == HashToken("y") {
		t.Fatalf("bad hash %q", h)
	}
}

func TestCreateCodeReplacesPreviousCode(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	first, _, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.State().Codes); n != 1 {
		t.Fatalf("codes=%d, want 1", n)
	}
	if _, _, err := s.RedeemCode(first, "Bot", "b", "", nil, now); err != ErrNotFound {
		t.Fatalf("old code err=%v", err)
	}
	if _, _, err := s.RedeemCode(second, "Bot", "b", "", nil, now); err != nil {
		t.Fatalf("new code err=%v", err)
	}
}

func TestRedeemAcceptsLooseFormatting(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	code, _, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	loose := " " + strings.ToLower(code) + " "
	if _, _, err := s.RedeemCode(loose, "Bot", "b", "", nil, now); err != nil {
		t.Fatalf("loose code err=%v", err)
	}
}

func TestRedeemCodeErrors(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	if _, _, err := s.RedeemCode("ZZZZ-ZZZZ", "Bot", "b", "", nil, now); err != ErrNotFound {
		t.Fatalf("unknown code err=%v", err)
	}
	if _, _, err := s.RedeemCode("not a code", "Bot", "b", "", nil, now); err != ErrNotFound {
		t.Fatalf("malformed code err=%v", err)
	}
	expired, _, err := s.CreateCode("u1", now.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemCode(expired, "Bot", "b", "", nil, now); err != ErrExpired {
		t.Fatalf("expired code err=%v", err)
	}
	code, _, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	key := codeKey(t, code)
	s.mu.Lock()
	s.data.Codes[key].Attempts = maxCodeAttempts
	s.mu.Unlock()
	if _, _, err := s.RedeemCode(code, "Bot", "b", "", nil, now); err != ErrAttempts {
		t.Fatalf("exhausted code err=%v", err)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	token, _, err := s.CreateSession("u1", now.Add(-31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Session(token, now); ok {
		t.Fatal("expired session accepted")
	}
	if n := len(s.State().Sessions); n != 0 {
		t.Fatalf("sessions=%d, want 0", n)
	}
	token, csrf, err := s.CreateSession("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || csrf == "" || token == csrf {
		t.Fatalf("bad session secrets %q %q", token, csrf)
	}
	if _, ok := s.Session("bogus", now); ok {
		t.Fatal("bogus session accepted")
	}
	if err := s.DeleteSession(token); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Session(token, now); ok {
		t.Fatal("deleted session still valid")
	}
}

func TestOwnershipIsEnforced(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	inst := pair(t, s, "u1", now)
	if err := s.RenameInstallation(inst.ID, "u2", "Stolen"); err != ErrNotFound {
		t.Fatalf("foreign rename err=%v", err)
	}
	if got, ok := s.Installation(inst.ID); !ok || got.Name != "Bot" {
		t.Fatalf("rename leaked: %+v %v", got, ok)
	}
	if err := s.DeleteInstallation(inst.ID, "u2"); err != ErrNotFound {
		t.Fatalf("foreign delete err=%v", err)
	}
	if _, ok := s.Installation(inst.ID); !ok {
		t.Fatal("foreign delete removed installation")
	}
	if err := s.RenameInstallation(inst.ID, "u1", "  Renamed  "); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Installation(inst.ID); got.Name != "Renamed" {
		t.Fatalf("name=%q", got.Name)
	}
	if err := s.AddCommand(Command{ID: "cmd_1", InstallationID: inst.ID, DiscordID: "u1", Command: "pause"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteInstallation(inst.ID, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Installation(inst.ID); ok {
		t.Fatal("installation not deleted")
	}
	if c := s.LastCommand(inst.ID); c != nil {
		t.Fatalf("orphan command left: %+v", c)
	}
	if err := s.DeleteInstallation(inst.ID, "u1"); err != ErrNotFound {
		t.Fatalf("second delete err=%v", err)
	}
}

func TestReadsReturnCopies(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.UpsertUser(User{ID: "u1", Username: "user"})
	inst := pair(t, s, "u1", now)
	bank := int64(5)
	h1 := int64(7)
	s.SetTelemetry(inst.ID, &Telemetry{
		Account: "Acc",
		Bank:    &bank,
		Profit:  &Interval{H1: &h1},
		Swarm:   &Swarm{Enabled: true},
	}, now)
	if err := s.AddCommand(Command{ID: "cmd_1", InstallationID: inst.ID, CreatedAt: now.UnixMilli()}); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Installation(inst.ID)
	got.Name = "MUTATED"
	got.Capabilities[0] = "MUTATED"
	got.Telemetry.Account = "MUTATED"
	*got.Telemetry.Bank = 99
	*got.Telemetry.Profit.H1 = 99
	got.Telemetry.Swarm.Enabled = false
	again, _ := s.Installation(inst.ID)
	if again.Name != "Bot" || again.Capabilities[0] != "pause" || again.Telemetry.Account != "Acc" ||
		*again.Telemetry.Bank != 5 || *again.Telemetry.Profit.H1 != 7 || !again.Telemetry.Swarm.Enabled {
		t.Fatalf("installation exposed internal pointers: %+v %+v", again, again.Telemetry)
	}

	list := s.InstallationsFor("u1")
	if len(list) != 1 {
		t.Fatalf("installations=%d", len(list))
	}
	list[0].Name = "MUTATED"
	if again, _ := s.Installation(inst.ID); again.Name != "Bot" {
		t.Fatal("InstallationsFor exposed internal pointers")
	}
	if other := s.InstallationsFor("u2"); len(other) != 0 {
		t.Fatalf("u2 saw %d installations", len(other))
	}

	token := sessionToken(t, s, "u1", now)
	sess, _ := s.Session(token, now)
	csrf := sess.CSRF
	sess.CSRF = "MUTATED"
	againSess, _ := s.Session(token, now)
	if againSess.CSRF != csrf {
		t.Fatal("session exposed internal pointer")
	}

	u, _ := s.User("u1")
	u.Username = "MUTATED"
	if againU, _ := s.User("u1"); againU.Username != "user" {
		t.Fatal("user exposed internal pointer")
	}

	cmd := s.LastCommand(inst.ID)
	cmd.State = "MUTATED"
	if againCmd := s.LastCommand(inst.ID); againCmd.State == "MUTATED" {
		t.Fatal("command exposed internal pointer")
	}

	st := s.State()
	st.Users["u1"].Username = "MUTATED"
	st.Installations[installationKey(inst.ID)].Name = "MUTATED"
	if againU, _ := s.User("u1"); againU.Username != "user" {
		t.Fatal("State exposed internal user pointer")
	}
	if again, _ := s.Installation(inst.ID); again.Name != "Bot" {
		t.Fatal("State exposed internal installation pointer")
	}
}

func TestSecretsAreHashedAtRest(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	code, _, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	_, cred, err := s.RedeemCode(code, "Bot", "b", "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.CreateSession("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNow(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	normalized, _ := NormalizeCode(code)
	for _, secret := range []string{normalized, code, cred, token} {
		if strings.Contains(text, secret) {
			t.Fatalf("state.json contains a raw secret")
		}
	}
	if !strings.Contains(text, HashToken(cred)) || !strings.Contains(text, HashToken(token)) {
		t.Fatal("state.json does not contain the expected hashes")
	}
}

func TestTelemetryIsDirtyUntilSaved(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	inst := pair(t, s, "u1", now)
	if err := s.SaveNow(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTelemetry(inst.ID, &Telemetry{Account: "Acc", State: "SCANNING"}, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SCANNING") {
		t.Fatal("SetTelemetry persisted eagerly")
	}
	if got, _ := s.Installation(inst.ID); got.Telemetry == nil || got.Telemetry.Account != "Acc" {
		t.Fatal("telemetry not visible in memory")
	}
	if err := s.SaveNow(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, ok := s2.Installation(inst.ID)
	if !ok || got.Telemetry == nil || got.Telemetry.Account != "Acc" || got.Telemetry.State != "SCANNING" {
		t.Fatalf("telemetry lost after reload: %+v", got)
	}
}

func TestSetOnlinePersistsImmediately(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	inst := pair(t, s, "u1", now)
	if err := s.SetOnline(inst.ID, true, now); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"online": true`) {
		t.Fatal("SetOnline did not persist")
	}
	if err := s.SetOnline(9999, true, now); err != ErrNotFound {
		t.Fatalf("missing installation err=%v", err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, _ := s2.Installation(inst.ID); !got.Online {
		t.Fatal("online flag lost")
	}
}

func TestOpenPrunesExpiredState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, _, err := s.CreateSession("u1", now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateCode("u1", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCommand(Command{ID: "cmd_old", InstallationID: 1, CreatedAt: now.Add(-8 * 24 * time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNow(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	st := s2.State()
	if len(st.Sessions) != 0 || len(st.Codes) != 0 || len(st.Commands) != 0 {
		t.Fatalf("prune missed: sessions=%d codes=%d commands=%d", len(st.Sessions), len(st.Codes), len(st.Commands))
	}
}

func TestOpenCreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("left temp file %q", e.Name())
		}
	}
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestLastCommandReturnsNewest(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	inst := pair(t, s, "u1", now)
	if err := s.AddCommand(Command{ID: "cmd_a", InstallationID: inst.ID, Command: "pause", CreatedAt: now.UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCommand(Command{ID: "cmd_b", InstallationID: inst.ID, Command: "resume", CreatedAt: now.Add(time.Second).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	if got := s.LastCommand(inst.ID); got == nil || got.ID != "cmd_b" {
		t.Fatalf("last command=%+v", got)
	}
	if err := s.UpdateCommand("cmd_b", "completed", "done"); err != nil {
		t.Fatal(err)
	}
	if got := s.LastCommand(inst.ID); got.State != "completed" || got.Reason != "done" {
		t.Fatalf("update missed: %+v", got)
	}
	if err := s.UpdateCommand("cmd_missing", "completed", ""); err != ErrNotFound {
		t.Fatalf("missing update err=%v", err)
	}
	if got := s.LastCommand(4242); got != nil {
		t.Fatalf("unknown installation command: %+v", got)
	}
}

func TestCommandRingIsBounded(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.mu.Lock()
	for i := 0; i < maxCommands+5; i++ {
		id := "cmd_" + installationKey(int64(i))
		s.data.Commands[id] = &Command{
			ID:             id,
			InstallationID: 1,
			CreatedAt:      now.Add(time.Duration(i) * time.Millisecond).UnixMilli(),
		}
	}
	st := s.data
	s.mu.Unlock()
	if !st.pruneCommands(now) {
		t.Fatal("pruneCommands reported no change")
	}
	if n := len(st.Commands); n != maxCommands {
		t.Fatalf("commands=%d, want %d", n, maxCommands)
	}
	if _, ok := st.Commands["cmd_0"]; ok {
		t.Fatal("oldest command survived the ring limit")
	}
	last := "cmd_" + installationKey(int64(maxCommands+4))
	if _, ok := st.Commands[last]; !ok {
		t.Fatal("newest command was pruned")
	}
}

func TestInstallationByCredential(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	code, _, err := s.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	inst, cred, err := s.RedeemCode(code, "Bot", "b", "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.InstallationByCredential(HashToken(cred))
	if !ok || got.ID != inst.ID {
		t.Fatalf("credential lookup failed: %+v %v", got, ok)
	}
	if _, ok := s.InstallationByCredential(cred); ok {
		t.Fatal("raw credential must not match")
	}
	if _, ok := s.InstallationByCredential(""); ok {
		t.Fatal("empty hash matched")
	}
}

func pair(t *testing.T, s *Store, discordID string, now time.Time) *Installation {
	t.Helper()
	code, _, err := s.CreateCode(discordID, now)
	if err != nil {
		t.Fatal(err)
	}
	inst, _, err := s.RedeemCode(code, "Bot", "0.1.2", "hive", []string{"pause"}, now)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func sessionToken(t *testing.T, s *Store, discordID string, now time.Time) string {
	t.Helper()
	token, _, err := s.CreateSession(discordID, now)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func codeKey(t *testing.T, code string) string {
	t.Helper()
	normalized, ok := NormalizeCode(code)
	if !ok {
		t.Fatalf("code %q does not normalize", code)
	}
	return HashToken(normalized)
}
