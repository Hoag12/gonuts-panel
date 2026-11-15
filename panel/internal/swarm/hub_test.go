package swarm

import (
	"testing"
	"time"
)

func TestCredentialsSurviveRestart(t *testing.T) {
	secret := []byte("a-stable-deploy-secret")
	first := NewWithSecret(secret)
	credential, contributor, err := first.Enroll(42, "discord", []string{"actub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(credential) != 48 || credential[:5] != "gnc1_" {
		t.Fatalf("credential=%q", credential)
	}
	if len(contributor) != 14 || contributor[:2] != "c_" {
		t.Fatalf("contributor=%q", contributor)
	}

	restarted := NewWithSecret(secret)
	id, _, ok := restarted.Authenticate(credential)
	if !ok || id != 42 {
		t.Fatalf("restart lost the credential: id=%d ok=%v", id, ok)
	}
	now := time.Now()
	accepted, _, ok := restarted.Observe(credential, "k1", []Observation{{
		Type: "ask", ItemKey: "minecraft:golden_apple|64", UnitPrice: 35000, At: now.UnixMilli(),
	}}, now)
	if !ok || accepted != 1 {
		t.Fatalf("restart rejected the upload: accepted=%d ok=%v", accepted, ok)
	}

	other := NewWithSecret([]byte("another-secret"))
	if _, _, ok := other.Authenticate(credential); ok {
		t.Fatal("a different secret accepted the credential")
	}
	if _, ok := restarted.authenticate("gnc1_" + credential[5:9] + "-" + credential[14:]); ok {
		t.Fatal("tampered credential accepted")
	}
}
