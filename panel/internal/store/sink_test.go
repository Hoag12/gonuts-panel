package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeSink struct {
	mu    sync.Mutex
	body  []byte
	saves int
}

func (f *fakeSink) LoadState() ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.body == nil {
		return nil, false, nil
	}
	return append([]byte(nil), f.body...), true, nil
}

func (f *fakeSink) SaveState(body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = append([]byte(nil), body...)
	f.saves++
	return nil
}

func (f *fakeSink) Close() error { return nil }

func TestOpenWithSinkRestoresAccountsAndSessions(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.UpsertUser(User{ID: "u1", Username: "actub"}); err != nil {
		t.Fatal(err)
	}
	token, _, err := fresh.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := fresh.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, credential, err := fresh.RedeemCode(code, "actub", "build", "hive", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(fresh.dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}

	// A redeploy hands the service an empty disk; the sink holds the account.
	sink := &fakeSink{body: body}
	restored, err := OpenWithSink(t.TempDir(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.User("u1"); !ok {
		t.Fatal("user missing after restore")
	}
	if _, ok := restored.Session(token, time.Now()); !ok {
		t.Fatal("session missing after restore")
	}
	if got, ok := restored.Installation(inst.ID); !ok || got.Name != "actub" {
		t.Fatalf("installation missing after restore: %+v %v", got, ok)
	}
	if _, ok := restored.InstallationByCredential(HashToken(credential)); !ok {
		t.Fatal("credential missing after restore")
	}

	if err := restored.UpsertUser(User{ID: "u2", Username: "second"}); err != nil {
		t.Fatal(err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	saved := append([]byte(nil), sink.body...)
	saves := sink.saves
	sink.mu.Unlock()
	if saves == 0 || !containsUser(saved, "u2") {
		t.Fatalf("sink was not updated (saves=%d)", saves)
	}
}

func TestOpenWithoutSinkIgnoresRemote(t *testing.T) {
	dir := t.TempDir()
	plain, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if _, err := OpenWithSink(dir, sink); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.body == nil {
		t.Fatal("opening with an empty sink should still seed it from disk")
	}
}

func containsUser(body []byte, id string) bool {
	var st State
	if err := json.Unmarshal(body, &st); err != nil {
		return false
	}
	_, ok := st.Users[id]
	return ok
}
