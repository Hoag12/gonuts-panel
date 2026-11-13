// Package auth holds the panel's browser-session and Discord OAuth helpers:
// opaque token generation, PKCE (S256), session/CSRF cookies, Origin checks,
// and the Discord authorization-code exchange.
//
// Secrets never leave this package except to the caller: tokens and OAuth codes
// are passed through arguments and return values, never logged.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	// CookieName is the browser cookie holding the opaque session token.
	CookieName = "gonuts_session"
	// CSRFHeader is the request header carrying the session's CSRF token.
	CSRFHeader = "X-Gonuts-Csrf"
	// OAuthCookie holds the OAuth state between authorize and callback.
	OAuthCookie = "gonuts_oauth"

	sessionMaxAge = 30 * 24 * 60 * 60 // 30 days, in seconds
	oauthMaxAge   = 10 * 60           // 10 minutes, in seconds
)

// RandomToken returns n cryptographically random bytes as unpadded base64url.
func RandomToken(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("auth: token size must be positive")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is the hex SHA-256 used by the store for session tokens.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Equal compares two secrets in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewVerifier returns a PKCE code verifier: 32 random bytes, 43 base64url
// characters, matching RFC 7636's 43..128 character range.
func NewVerifier() (string, error) {
	return RandomToken(32)
}

// Challenge derives the S256 PKCE challenge for a verifier.
func Challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE reports whether c is the S256 challenge of v.
func VerifyPKCE(v, c string) bool {
	return Equal(Challenge(v), c)
}

// CookieToken returns the raw session token from the request, or "".
func CookieToken(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// SetSessionCookie stores a session token in an HttpOnly, SameSite=Lax cookie.
func SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	setSessionCookie(w, token, secure, sessionMaxAge)
}

// SetSessionCookieSession stores the token without a Max-Age, so the browser
// drops it when it closes: the "remember me" unchecked case.
func SetSessionCookieSession(w http.ResponseWriter, token string, secure bool) {
	setSessionCookie(w, token, secure, 0)
}

func setSessionCookie(w http.ResponseWriter, token string, secure bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// SetOAuthCookie stores the OAuth state in a short-lived HttpOnly cookie.
func SetOAuthCookie(w http.ResponseWriter, state string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     OAuthCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   oauthMaxAge,
	})
}

// ClearOAuthCookie expires the OAuth state cookie.
func ClearOAuthCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     OAuthCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// OriginAllowedAny reports whether the request's Origin matches any of the
// configured origins. The first entry is the public base URL; the rest are
// alternate origins the operator reaches the panel through (a tailnet address,
// a second interface), so a mutation is not refused just because the browser
// used a different but equally trusted host.
func OriginAllowedAny(r *http.Request, bases []string) bool {
	for _, base := range bases {
		if base != "" && OriginAllowed(r, base) {
			return true
		}
	}
	return false
}

// OriginAllowed reports whether the request's Origin (or, when absent, its
// Referer) matches the scheme and host of base. Requests without either header
// are rejected: mutating requests must come from the panel's own origin.
func OriginAllowed(r *http.Request, base string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, b.Scheme) && strings.EqualFold(u.Host, b.Host)
}
