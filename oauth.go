// Package main implements clauth, a tiny OAuth2 helper that performs the same
// login `claude auth login` (Pro/Max subscription) performs and writes a
// credentials file the Claude Code CLI accepts verbatim.
//
// The protocol constants below were verified by disassembling the shipped
// Claude Code native binary (the real values it uses), not guessed.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OAuth / endpoint constants (verified against Claude Code 2.1.x).
const (
	clientID             = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	authorizeURLClaudeAI = "https://claude.com/cai/oauth/authorize"
	authorizeURLConsole  = "https://platform.claude.com/oauth/authorize"
	tokenURL             = "https://platform.claude.com/v1/oauth/token"
	profileURL           = "https://api.anthropic.com/api/oauth/profile"
	manualRedirectURL    = "https://platform.claude.com/oauth/code/callback"
	userAgent            = "clauth"
)

// scopes requested for a subscription (claude.ai) login — matches the CLI.
var scopes = []string{
	"org:create_api_key",
	"user:profile",
	"user:inference",
	"user:sessions:claude_code",
	"user:mcp_servers",
	"user:file_upload",
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return b64url(b[:])
}

// newPKCE returns (codeVerifier, codeChallenge, state).
func newPKCE() (verifier, challenge, state string) {
	verifier = randToken()
	sum := sha256.Sum256([]byte(verifier))
	challenge = b64url(sum[:])
	state = randToken()
	return
}

// buildAuthorizeURL constructs the browser authorize URL.
func buildAuthorizeURL(challenge, state, redirectURI string, useClaudeAI bool) string {
	base := authorizeURLConsole
	if useClaudeAI {
		base = authorizeURLClaudeAI
	}
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return base + "?" + q.Encode()
}

// parsePastedCode accepts "code#state", "code", or a full callback URL.
func parsePastedCode(pasted string) (code, state string) {
	pasted = strings.TrimSpace(pasted)
	if strings.HasPrefix(pasted, "http://") || strings.HasPrefix(pasted, "https://") {
		if u, err := url.Parse(pasted); err == nil {
			return u.Query().Get("code"), u.Query().Get("state")
		}
	}
	if i := strings.IndexByte(pasted, '#'); i >= 0 {
		return strings.TrimSpace(pasted[:i]), strings.TrimSpace(pasted[i+1:])
	}
	return pasted, ""
}

// ---------------------------------------------------------------------------
// Token exchange + profile
// ---------------------------------------------------------------------------

type tokenResp struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshTokenExpiresIn *int64 `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
	Account               *struct {
		UUID         string `json:"uuid"`
		EmailAddress string `json:"email_address"`
	} `json:"account"`
}

func exchangeCode(code, verifier, state, redirectURI string) (*tokenResp, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
		"code_verifier": verifier,
		"state":         state,
	})
	req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, trim(raw))
	}
	var tr tokenResp
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned no access_token: %s", trim(raw))
	}
	return &tr, nil
}

type profileResp struct {
	Account struct {
		HasClaudeMax bool `json:"has_claude_max"`
		HasClaudePro bool `json:"has_claude_pro"`
	} `json:"account"`
	Organization struct {
		OrganizationType string `json:"organization_type"`
		RateLimitTier    string `json:"rate_limit_tier"`
	} `json:"organization"`
}

// fetchSubscription is a best-effort lookup that mirrors what the native login
// stores. It never fails the login — a nil result just leaves the fields null.
func fetchSubscription(accessToken string) (subscription, rateLimitTier *string) {
	req, _ := http.NewRequest(http.MethodGet, profileURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var p profileResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&p); err != nil {
		return nil, nil
	}
	var sub string
	switch {
	case p.Account.HasClaudeMax || p.Organization.OrganizationType == "claude_max":
		sub = "max"
	case p.Account.HasClaudePro || p.Organization.OrganizationType == "claude_pro":
		sub = "pro"
	}
	if sub != "" {
		subscription = &sub
	}
	if p.Organization.RateLimitTier != "" {
		tier := p.Organization.RateLimitTier
		rateLimitTier = &tier
	}
	return subscription, rateLimitTier
}

// ---------------------------------------------------------------------------
// Credentials file
// ---------------------------------------------------------------------------

type claudeAiOauth struct {
	AccessToken           string   `json:"accessToken"`
	RefreshToken          string   `json:"refreshToken,omitempty"`
	ExpiresAt             int64    `json:"expiresAt"`
	RefreshTokenExpiresAt *int64   `json:"refreshTokenExpiresAt,omitempty"`
	Scopes                []string `json:"scopes"`
	SubscriptionType      *string  `json:"subscriptionType"`
	RateLimitTier         *string  `json:"rateLimitTier"`
	ClientID              string   `json:"clientId"`
}

func credentialsPath() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, ".credentials.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", ".credentials.json")
}

// nowMillis is a var so tests can hold it steady.
var nowMillis = func() int64 { return time.Now().UnixMilli() }

// buildCredential turns a token response + subscription info into the exact
// object the CLI serializes under "claudeAiOauth".
func buildCredential(tok *tokenResp, sub, tier *string) claudeAiOauth {
	now := nowMillis()
	sc := strings.Fields(tok.Scope)
	if len(sc) == 0 {
		sc = append([]string(nil), scopes...)
	}
	c := claudeAiOauth{
		AccessToken:      tok.AccessToken,
		RefreshToken:     tok.RefreshToken,
		ExpiresAt:        now + tok.ExpiresIn*1000,
		Scopes:           sc,
		SubscriptionType: sub,
		RateLimitTier:    tier,
		ClientID:         clientID,
	}
	if tok.RefreshTokenExpiresIn != nil {
		v := now + *tok.RefreshTokenExpiresIn*1000
		c.RefreshTokenExpiresAt = &v
	}
	return c
}

// writeCredentials merges the credential into any existing file (preserving
// unrelated top-level keys) and writes it 0600, atomically.
func writeCredentials(c claudeAiOauth) (string, error) {
	path := credentialsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	root := map[string]json.RawMessage{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &root) // ignore a corrupt existing file
	}
	oauthRaw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	root["claudeAiOauth"] = oauthRaw
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	out = append(out, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// loginSummary is the result of a completed login.
type loginSummary struct {
	Path             string
	SubscriptionType *string
	Scopes           []string
	ExpiresInSeconds int64
	HasRefreshToken  bool
	Email            string
}

// finishLogin runs the tail of the flow: exchange -> profile -> write file.
func finishLogin(code, verifier, state, redirectURI string) (*loginSummary, error) {
	tok, err := exchangeCode(code, verifier, state, redirectURI)
	if err != nil {
		return nil, err
	}
	sub, tier := fetchSubscription(tok.AccessToken)
	c := buildCredential(tok, sub, tier)
	path, err := writeCredentials(c)
	if err != nil {
		return nil, err
	}
	sum := &loginSummary{
		Path:             path,
		SubscriptionType: sub,
		Scopes:           c.Scopes,
		ExpiresInSeconds: tok.ExpiresIn,
		HasRefreshToken:  tok.RefreshToken != "",
	}
	if tok.Account != nil {
		sum.Email = tok.Account.EmailAddress
		if sum.Email == "" {
			sum.Email = tok.Account.UUID
		}
	}
	return sum, nil
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
