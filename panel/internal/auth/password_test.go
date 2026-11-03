package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

// cheapIterations keeps the tests fast; VerifyPassword accepts any count in
// range, so a low-count hash exercises the real code path.
const cheapIterations = 1000

func TestHashPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct horse", cheapIterations)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || parts[1] != "1000" {
		t.Fatalf("encoded=%q", encoded)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != 16 {
		t.Fatalf("salt=%q err=%v", parts[2], err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) != 32 {
		t.Fatalf("key=%q err=%v", parts[3], err)
	}
	if strings.Contains(encoded, "correct horse") {
		t.Fatal("encoded hash contains the password")
	}
	if !VerifyPassword(encoded, "correct horse") {
		t.Fatal("round trip failed")
	}
	if VerifyPassword(encoded, "correct horsf") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword(encoded, "") {
		t.Fatal("empty password accepted")
	}

	// A second hash of the same password must use a fresh salt.
	other, err := HashPassword("correct horse", cheapIterations)
	if err != nil {
		t.Fatal(err)
	}
	if other == encoded {
		t.Fatal("two hashes of one password are identical")
	}
	if !VerifyPassword(other, "correct horse") {
		t.Fatal("second hash does not verify")
	}
}

func TestHashPasswordUsesDefaultIterations(t *testing.T) {
	encoded, err := HashPassword("hunter2", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "pbkdf2-sha256$600000$") {
		t.Fatalf("default iterations missing: %q", encoded)
	}
	if !VerifyPassword(encoded, "hunter2") {
		t.Fatal("default-iteration hash does not verify")
	}
}

func TestHashPasswordRejectsShortPasswordAndBadIterations(t *testing.T) {
	for _, pw := range []string{"", "a", "abc"} {
		if _, err := HashPassword(pw, cheapIterations); err == nil {
			t.Fatalf("short password %q accepted", pw)
		}
	}
	if _, err := HashPassword("abcd", -1); err == nil {
		t.Fatal("negative iterations accepted")
	}
	if _, err := HashPassword("abcd", MaxPasswordIterations+1); err == nil {
		t.Fatal("over-cap iterations accepted")
	}
	if _, err := HashPassword("abcd", MinPasswordLength); err != nil {
		t.Fatalf("single-character over-minimum password rejected: %v", err)
	}
}

func TestVerifyPasswordRejectsTamperedFields(t *testing.T) {
	encoded, err := HashPassword("correct horse", cheapIterations)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, "$")

	// Flip one character of the salt, then of the key.
	flip := func(s string) string {
		b := []byte(s)
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		return string(b)
	}
	tamperedSalt := strings.Join([]string{parts[0], parts[1], flip(parts[2]), parts[3]}, "$")
	if VerifyPassword(tamperedSalt, "correct horse") {
		t.Fatal("tampered salt accepted")
	}
	tamperedKey := strings.Join([]string{parts[0], parts[1], parts[2], flip(parts[3])}, "$")
	if VerifyPassword(tamperedKey, "correct horse") {
		t.Fatal("tampered key accepted")
	}
}

func TestVerifyPasswordFailsClosedOnMalformedInput(t *testing.T) {
	encoded, err := HashPassword("correct horse", cheapIterations)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, "$")

	salt := parts[2]
	key := parts[3]
	shortSalt := base64.RawStdEncoding.EncodeToString([]byte("short"))
	shortKey := base64.RawStdEncoding.EncodeToString([]byte("short"))

	cases := map[string]string{
		"empty":               "",
		"plaintext":           "correct horse",
		"too few fields":      "pbkdf2-sha256$1000$" + salt,
		"too many fields":     encoded + "$extra",
		"unknown scheme":      "pbkdf2-sha1$1000$" + salt + "$" + key,
		"non-numeric iters":   "pbkdf2-sha256$abc$" + salt + "$" + key,
		"zero iters":          "pbkdf2-sha256$0$" + salt + "$" + key,
		"negative iters":      "pbkdf2-sha256$-5$" + salt + "$" + key,
		"oversized iters":     "pbkdf2-sha256$" + strings.Repeat("9", 30) + "$" + salt + "$" + key,
		"over cap iters":      "pbkdf2-sha256$" + "2000001" + "$" + salt + "$" + key,
		"empty salt":          "pbkdf2-sha256$1000$$" + key,
		"short salt":          "pbkdf2-sha256$1000$" + shortSalt + "$" + key,
		"short key":           "pbkdf2-sha256$1000$" + salt + "$" + shortKey,
		"padded salt":         "pbkdf2-sha256$1000$" + salt + "==$" + key,
		"invalid base64 salt": "pbkdf2-sha256$1000$!!!!$" + key,
		"invalid base64 key":  "pbkdf2-sha256$1000$" + salt + "$!!!!",
	}
	for name, encoded := range cases {
		if VerifyPassword(encoded, "correct horse") {
			t.Fatalf("%s: malformed hash accepted", name)
		}
	}
}
