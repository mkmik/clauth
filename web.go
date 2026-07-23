package main

import (
	"html/template"
	"net/http"
	"sync"
)

// pendingEntry holds the PKCE verifier for an in-flight login, keyed by state.
type pendingEntry struct {
	verifier string
	redirect string
}

// server holds the manual-flow web app state.
type server struct {
	mu       sync.Mutex
	pending  map[string]pendingEntry
	order    []string // insertion order, for bounded eviction
	claudeAI bool
}

func newServer(claudeAI bool) *server {
	return &server{pending: map[string]pendingEntry{}, claudeAI: claudeAI}
}

func (s *server) remember(state string, e pendingEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[state] = e
	s.order = append(s.order, state)
	for len(s.order) > 32 {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.pending, old)
	}
}

// take removes and returns the entry for state; if state is unknown it falls
// back to the most recent pending entry (single-user, single-flow app).
func (s *server) take(state string) (pendingEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.pending[state]; ok {
		delete(s.pending, state)
		return e, true
	}
	if n := len(s.order); n > 0 {
		last := s.order[n-1]
		if e, ok := s.pending[last]; ok {
			delete(s.pending, last)
			return e, true
		}
	}
	return pendingEntry{}, false
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/finish", s.handleFinish)
	return mux
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	verifier, challenge, state := newPKCE()
	s.remember(state, pendingEntry{verifier: verifier, redirect: manualRedirectURL})
	authURL := buildAuthorizeURL(challenge, state, manualRedirectURL, s.claudeAI)
	render(w, http.StatusOK, pageData{AuthURL: authURL})
}

func (s *server) handleFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pasted := r.FormValue("pasted")
	code, state := parsePastedCode(pasted)
	if code == "" {
		render(w, http.StatusBadRequest, pageData{Error: "Nothing to exchange — paste the code#state value."})
		return
	}
	entry, ok := s.take(state)
	if !ok {
		render(w, http.StatusBadRequest, pageData{Error: "No pending login. Reload this page and start again."})
		return
	}
	sum, err := finishLogin(code, entry.verifier, state, entry.redirect)
	if err != nil {
		render(w, http.StatusBadRequest, pageData{Error: "Login failed. " + err.Error()})
		return
	}
	render(w, http.StatusOK, pageData{Summary: sum})
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

type pageData struct {
	AuthURL string
	Error   string
	Summary *loginSummary
}

func (p pageData) CredPath() string { return credentialsPath() }
func (p pageData) Scopes() string   { return joinScopes() }
func (p pageData) ClientID() string { return clientID }

func joinScopes() string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func render(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTmpl.Execute(w, d)
}

var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

const pageHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude Code login</title><style>
 :root{color-scheme:light dark}
 body{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;max-width:720px;
   margin:6vh auto;padding:0 20px;background:#faf9f7;color:#1a1a19}
 @media(prefers-color-scheme:dark){body{background:#1a1817;color:#ece9e3}}
 h1{font-size:22px;margin:0 0 4px} .sub{opacity:.7;margin:0 0 28px}
 .card{border:1px solid #d9d4cc;border-radius:12px;padding:20px 22px;margin:0 0 18px;
   background:rgba(255,255,255,.5)}
 @media(prefers-color-scheme:dark){.card{border-color:#3a3632;background:rgba(255,255,255,.03)}}
 .card h2{font-size:15px;margin:0 0 10px;letter-spacing:.02em}
 a.btn,button{font:inherit;font-weight:600;background:#c96442;color:#fff;border:0;
   border-radius:8px;padding:10px 16px;cursor:pointer;text-decoration:none;display:inline-block}
 input[type=text]{width:100%;box-sizing:border-box;font:13px ui-monospace,monospace;
   padding:10px;border:1px solid #cfc9c0;border-radius:8px;margin:8px 0;background:transparent;color:inherit}
 code{font:13px ui-monospace,monospace;background:rgba(128,128,128,.15);padding:1px 5px;border-radius:4px}
 .ok{color:#2e7d32}.err{color:#c62828;white-space:pre-wrap}
 .muted{opacity:.65;font-size:13px}
</style></head><body>
<h1>Sign in to Claude Code</h1>
<p class="sub">Writes <code>{{.CredPath}}</code> on this machine — the same
credentials file <code>claude auth login</code> creates for your Pro/Max plan.</p>
{{if .Summary}}
<div class=card><h2 class=ok>&#10003; Signed in</h2>
<p>Wrote <code>{{.Summary.Path}}</code>.</p>
<ul class=muted>
<li>account: {{if .Summary.Email}}{{.Summary.Email}}{{else}}(unknown){{end}}</li>
<li>subscription: {{if .Summary.SubscriptionType}}{{.Summary.SubscriptionType}}{{else}}null{{end}}</li>
<li>scopes: {{range $i, $s := .Summary.Scopes}}{{if $i}} {{end}}{{$s}}{{end}}</li>
<li>access token expires in: {{.Summary.ExpiresInSeconds}} s</li>
<li>refresh token: {{if .Summary.HasRefreshToken}}yes{{else}}no{{end}}</li></ul>
<p>You can close this tab and run <code>claude</code>.</p></div>
{{else}}
{{if .Error}}<div class=card><p class=err>{{.Error}}</p>
<p><a class=btn href="/">Try again</a></p></div>{{end}}
<div class=card><h2>1 &middot; Open this link and approve</h2>
<p class=muted>Opens in your own browser. Sign in to Claude and approve access.</p>
<p><a class=btn target=_blank rel=noopener href="{{.AuthURL}}">Open Claude sign in &nearr;</a></p>
<p class=muted>Or copy the URL:</p>
<input type=text readonly onclick="this.select()" value="{{.AuthURL}}">
</div>
<div class=card><h2>2 &middot; Paste the code back here</h2>
<p class=muted>After approving, Claude shows a code like <code>abc123#xyz789</code>.
Paste it below — it is exchanged for tokens and written to this machine.</p>
<form method=post action="/finish">
<input type=text name=pasted placeholder="code#state" autofocus>
<button type=submit>Finish sign in</button></form></div>
{{end}}
<p class="muted">client_id <code>{{.ClientID}}</code> &middot; scopes: {{.Scopes}}</p>
</body></html>`
