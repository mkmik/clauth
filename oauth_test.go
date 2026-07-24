package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	verifier, challenge, state := newPKCE()
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge %q != sha256(verifier) %q", challenge, want)
	}
	for _, s := range []string{verifier, challenge, state} {
		if strings.ContainsAny(s, "=+/") {
			t.Fatalf("token %q is not base64url-unpadded", s)
		}
	}
	if verifier == state {
		t.Fatal("verifier and state should differ")
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	u := buildAuthorizeURL("CHAL", "STATE", "https://platform.claude.com/oauth/code/callback", true)
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Host + parsed.Path; got != "claude.com/cai/oauth/authorize" {
		t.Fatalf("authorize endpoint = %q", got)
	}
	q := parsed.Query()
	cases := map[string]string{
		"code":                  "true",
		"client_id":             clientID,
		"response_type":         "code",
		"code_challenge":        "CHAL",
		"code_challenge_method": "S256",
		"state":                 "STATE",
		"scope":                 strings.Join(scopes, " "),
	}
	for k, want := range cases {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	// console variant
	uc := buildAuthorizeURL("C", "S", "r", false)
	if !strings.HasPrefix(uc, authorizeURLConsole) {
		t.Errorf("console authorize url = %q", uc)
	}
}

func TestParsePastedCode(t *testing.T) {
	cases := []struct{ in, code, state string }{
		{"abc#xyz", "abc", "xyz"},
		{"  abc#xyz  ", "abc", "xyz"},
		{"onlycode", "onlycode", ""},
		{"https://x/cb?code=AA&state=BB", "AA", "BB"},
	}
	for _, c := range cases {
		code, state := parsePastedCode(c.in)
		if code != c.code || state != c.state {
			t.Errorf("parsePastedCode(%q) = (%q,%q), want (%q,%q)", c.in, code, state, c.code, c.state)
		}
	}
}

func TestBuildCredentialShape(t *testing.T) {
	old := nowMillis
	nowMillis = func() int64 { return 1_000_000 }
	defer func() { nowMillis = old }()

	rte := int64(3600)
	max := "max"
	tier := "default_claude_max_5x"
	tok := &tokenResp{
		AccessToken:           "AT",
		RefreshToken:          "RT",
		ExpiresIn:             60,
		RefreshTokenExpiresIn: &rte,
		Scope:                 "user:inference user:profile",
	}
	c := buildCredential(tok, &max, &tier)
	if c.ExpiresAt != 1_000_000+60*1000 {
		t.Errorf("expiresAt = %d", c.ExpiresAt)
	}
	if c.RefreshTokenExpiresAt == nil || *c.RefreshTokenExpiresAt != 1_000_000+3600*1000 {
		t.Errorf("refreshTokenExpiresAt = %v", c.RefreshTokenExpiresAt)
	}
	if c.ClientID != clientID {
		t.Errorf("clientId = %q", c.ClientID)
	}
	if len(c.Scopes) != 2 || c.Scopes[0] != "user:inference" {
		t.Errorf("scopes = %v", c.Scopes)
	}

	// Marshaled keys must match what the CLI reads.
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"accessToken", "refreshToken", "expiresAt", "scopes", "subscriptionType", "rateLimitTier", "clientId"} {
		if _, ok := m[k]; !ok {
			t.Errorf("credential JSON missing key %q", k)
		}
	}
}

func TestWriteCredentialsMergesAndPerms(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	path := filepath.Join(dir, ".credentials.json")
	// Pre-existing unrelated key must survive.
	if err := os.WriteFile(path, []byte(`{"otherKey":123}`), 0o600); err != nil {
		t.Fatal(err)
	}

	sub := "max"
	c := buildCredential(&tokenResp{AccessToken: "AT", ExpiresIn: 10}, &sub, nil)
	got, err := writeCredentials(c)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("path = %q, want %q", got, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perms = %o, want 600", perm)
	}
	var root map[string]json.RawMessage
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := root["otherKey"]; !ok {
		t.Error("otherKey was not preserved")
	}
	if _, ok := root["claudeAiOauth"]; !ok {
		t.Error("claudeAiOauth was not written")
	}
}

func TestPublicURL(t *testing.T) {
	if got := publicURL("orca-cookie", "exe.xyz", 1234); got != "https://orca-cookie.exe.xyz:1234/" {
		t.Errorf("publicURL short host = %q", got)
	}
	if got := publicURL("vm.example.com", "exe.xyz", 80); got != "https://vm.example.com:80/" {
		t.Errorf("publicURL fqdn = %q", got)
	}
	if got := publicURL("localhost", "exe.xyz", 8080); got != "http://localhost:8080/" {
		t.Errorf("publicURL localhost = %q", got)
	}
}

func TestServerFinishedIdempotent(t *testing.T) {
	s := newServer(true)
	select {
	case <-s.done:
		t.Fatal("done should be open before finish")
	default:
	}
	s.finished()
	s.finished() // must not panic on second close
	select {
	case <-s.done:
	default:
		t.Fatal("done should be closed after finished()")
	}
}

func TestServerTakeFallback(t *testing.T) {
	s := newServer(true)
	s.remember("state1", pendingEntry{verifier: "v1", redirect: "r"})
	// exact match
	if e, ok := s.take("state1"); !ok || e.verifier != "v1" {
		t.Fatalf("exact take failed: %v %v", e, ok)
	}
	// fallback to newest when state unknown
	s.remember("state2", pendingEntry{verifier: "v2", redirect: "r"})
	if e, ok := s.take("unknown"); !ok || e.verifier != "v2" {
		t.Fatalf("fallback take failed: %v %v", e, ok)
	}
	// now empty
	if _, ok := s.take("anything"); ok {
		t.Fatal("expected empty store")
	}
}
