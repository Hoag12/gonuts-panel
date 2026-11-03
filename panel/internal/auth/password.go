package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Local sign-in password hashing. The encoded form is
//
//	pbkdf2-sha256$<iterations>$<base64 salt>$<base64 key>
//
// with unpadded standard base64 on both fields. Hashing and verification are
// pure functions: nothing is logged, and the plaintext password never leaves
// the caller.
const (
	// DefaultPasswordIterations is used when HashPassword is asked for 0.
	DefaultPasswordIterations = 600000
	// MaxPasswordIterations caps verification work. A state file or an env var
	// with an absurd iteration count must fail closed instead of burning CPU.
	MaxPasswordIterations = 2000000
	// MinPasswordLength is the shortest accepted password.
	MinPasswordLength = 4

	passwordScheme   = "pbkdf2-sha256"
	passwordSaltSize = 16
	passwordKeySize  = 32
)

// HashPassword derives a PBKDF2-HMAC-SHA256 hash of password. A zero iteration
// count selects DefaultPasswordIterations; anything outside 1..MaxPasswordIterations
// is rejected. The password must be at least MinPasswordLength bytes.
func HashPassword(password string, iterations int) (string, error) {
	if len(password) < MinPasswordLength {
		return "", fmt.Errorf("auth: password must be at least %d characters", MinPasswordLength)
	}
	if iterations == 0 {
		iterations = DefaultPasswordIterations
	}
	if iterations < 1 || iterations > MaxPasswordIterations {
		return "", fmt.Errorf("auth: iterations must be between 1 and %d", MaxPasswordIterations)
	}
	salt := make([]byte, passwordSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read random: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, passwordKeySize)
	if err != nil {
		return "", fmt.Errorf("auth: derive key: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s", passwordScheme, iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches encoded. Any malformed
// encoding, unknown scheme, wrong salt/key size, or out-of-range iteration
// count returns false rather than an error, so a bad configuration cannot
// accidentally authenticate.
func VerifyPassword(encoded, password string) bool {
	iterations, salt, want, ok := parsePasswordHash(encoded)
	if !ok {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidPasswordHash reports whether encoded is a well-formed encoded hash. It
// validates exactly what VerifyPassword validates (scheme, iteration range,
// salt and key sizes, strict unpadded base64) but derives no key, so startup can
// reject a typo instead of failing every sign-in. An empty string is invalid.
func ValidPasswordHash(encoded string) bool {
	_, _, _, ok := parsePasswordHash(encoded)
	return ok
}

// parsePasswordHash decodes and validates encoded without running PBKDF2. It
// returns ok=false for an unknown scheme, a non-numeric or out-of-range
// iteration count, or a salt/key of the wrong size or encoding.
func parsePasswordHash(encoded string) (iterations int, salt, key []byte, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return 0, nil, nil, false
	}
	// Atoi fails closed on non-numeric or oversized counts before any
	// derivation work.
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > MaxPasswordIterations {
		return 0, nil, nil, false
	}
	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(salt) != passwordSaltSize {
		return 0, nil, nil, false
	}
	key, err = base64.RawStdEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(key) != passwordKeySize {
		return 0, nil, nil, false
	}
	return iterations, salt, key, true
}
