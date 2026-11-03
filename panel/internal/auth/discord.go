package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gonutspanel/internal/config"
)

// DiscordUser is the subset of the Discord user object the panel stores.
type DiscordUser struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	GlobalName string `json:"global_name"`
	Avatar     string `json:"avatar"`
}

// Discord performs the authorization-code exchange and profile lookup against
// Discord. The zero value is usable for testing when every field is set.
type Discord struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthorizeURL string
	TokenURL     string
	UserURL      string
	HTTP         *http.Client
}

var discordHTTPClient = &http.Client{Timeout: 15 * time.Second}

// NewDiscord builds a Discord client from the panel configuration. RedirectURI
// is left empty: the web layer derives it from PUBLIC_BASE_URL, which owns the
// externally visible callback path.
func NewDiscord(cfg config.Config) *Discord {
	apiBase := strings.TrimRight(cfg.DiscordAPIBase, "/")
	return &Discord{
		ClientID:     cfg.DiscordClientID,
		ClientSecret: cfg.DiscordClientSecret,
		AuthorizeURL: cfg.OAuthAuthorizeURL,
		TokenURL:     apiBase + "/oauth2/token",
		UserURL:      apiBase + "/users/@me",
		HTTP:         discordHTTPClient,
	}
}

func (d *Discord) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return discordHTTPClient
}

// AuthorizeURLFor returns the Discord authorize URL for the given state and
// PKCE challenge. The redirect URI is whatever the caller configured.
func (d *Discord) AuthorizeURLFor(state, challenge string) string {
	q := url.Values{
		"client_id":             {d.ClientID},
		"redirect_uri":          {d.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"identify"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return d.AuthorizeURL + "?" + q.Encode()
}

// Exchange redeems an authorization code for an access token. The token is
// returned to the caller and never logged.
func (d *Discord) Exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"client_id":     {d.ClientID},
		"client_secret": {d.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {d.RedirectURI},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("discord token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := d.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("discord token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discord token exchange: %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("discord token exchange: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("discord token exchange: empty access token")
	}
	return out.AccessToken, nil
}

// Me fetches the authorized user's profile.
func (d *Discord) Me(ctx context.Context, accessToken string) (DiscordUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserURL, nil)
	if err != nil {
		return DiscordUser{}, fmt.Errorf("discord user: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := d.client().Do(req)
	if err != nil {
		return DiscordUser{}, fmt.Errorf("discord user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DiscordUser{}, fmt.Errorf("discord user: %s", resp.Status)
	}
	var u DiscordUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u); err != nil {
		return DiscordUser{}, fmt.Errorf("discord user: %w", err)
	}
	if u.ID == "" {
		return DiscordUser{}, errors.New("discord user: id missing")
	}
	return u, nil
}
