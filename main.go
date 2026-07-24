package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const defaultPort = 1234

func main() {
	var (
		port        = flag.Int("port", defaultPort, "preferred port; the next free port is used if it is taken")
		host        = flag.String("host", "0.0.0.0", "bind address")
		baseDomain  = flag.String("base-domain", envOr("CLAUTH_BASE_DOMAIN", "exe.xyz"), "domain appended to a short hostname to form the public URL")
		publicHost  = flag.String("public-host", os.Getenv("CLAUTH_PUBLIC_HOST"), "override the hostname used in the printed public URL")
		console     = flag.Bool("console", false, "use the console (API credits) authorize endpoint instead of the claude.ai subscription one")
		printURL    = flag.Bool("print-url", false, "headless: print a manual authorize URL (and the verifier/state to reuse) and exit")
		exchange    = flag.String("exchange", "", "headless: exchange a pasted CODE#STATE and write credentials")
		verifierArg = flag.String("verifier", "", "PKCE verifier (with -exchange)")
		stateArg    = flag.String("state", "", "OAuth state (with -exchange)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("clauth", version)
	case *printURL:
		cliPrintURL(!*console)
	case *exchange != "":
		cliExchange(*exchange, *verifierArg, *stateArg)
	default:
		serve(*host, *port, *baseDomain, *publicHost, !*console)
	}
}

// serve picks a port, prints the public URL, and runs the web app.
func serve(host string, preferred int, baseDomain, publicHostOverride string, claudeAI bool) {
	ln, actualPort, err := listen(host, preferred)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clauth: could not bind a port:", err)
		os.Exit(1)
	}
	if actualPort != preferred {
		fmt.Fprintf(os.Stderr, "clauth: port %d was taken, using %d instead\n", preferred, actualPort)
	}

	pub := publicURL(publicHostOverride, baseDomain, actualPort)
	srv := newServer(claudeAI)

	fmt.Println()
	fmt.Println("  clauth is ready. Open this URL in your browser to sign in to Claude Code:")
	fmt.Println()
	fmt.Println("      " + pub)
	fmt.Println()
	fmt.Println("  (Shelley, please share the link above with the user.)")
	fmt.Println("  Credentials will be written to: " + credentialsPath())
	fmt.Println("  Press Ctrl-C to stop.")
	fmt.Println()

	httpSrv := &http.Server{Handler: srv.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "clauth:", err)
			os.Exit(1)
		}
	}()

	// Run until a login succeeds (so `curl … | sh` returns) or we're interrupted.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-srv.done:
		fmt.Println("  Signed in — credentials written. Exiting.")
	case <-sig:
		fmt.Println("\n  Interrupted — exiting.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

// listen binds host:preferred, falling back to an OS-assigned free port.
func listen(host string, preferred int) (net.Listener, int, error) {
	if ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, preferred)); err == nil {
		return ln, preferred, nil
	}
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		return nil, 0, err
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

// publicURL builds the URL the user should open, from (in priority order):
// an explicit override, the exe.dev metadata name, or the OS hostname; a short
// name gets baseDomain appended.
func publicURL(override, baseDomain string, port int) string {
	host := override
	if host == "" {
		host = metadataName()
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	if host == "" {
		host = "localhost"
	}
	if !strings.Contains(host, ".") && host != "localhost" && baseDomain != "" {
		host = host + "." + baseDomain
	}
	scheme := "https"
	if host == "localhost" || strings.HasPrefix(host, "127.") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, port)
}

// metadataName reads the VM name from the exe.dev metadata service.
// Best-effort: returns "" if unreachable.
func metadataName() string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://169.254.169.254/")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var m struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return ""
	}
	return m.Name
}

// ---------------------------------------------------------------------------
// Headless helpers
// ---------------------------------------------------------------------------

func cliPrintURL(claudeAI bool) {
	verifier, challenge, state := newPKCE()
	url := buildAuthorizeURL(challenge, state, manualRedirectURL, claudeAI)
	fmt.Println("# Open this URL, approve, then run:")
	fmt.Printf("#   clauth -exchange 'CODE#STATE' -verifier %s -state %s\n", verifier, state)
	fmt.Println(url)
}

func cliExchange(pasted, verifier, state string) {
	code, pastedState := parsePastedCode(pasted)
	if state == "" {
		state = pastedState
	}
	if code == "" || verifier == "" || state == "" {
		fmt.Fprintln(os.Stderr, "need -exchange CODE#STATE, -verifier, and -state")
		os.Exit(2)
	}
	sum, err := finishLogin(code, verifier, state, manualRedirectURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clauth:", err)
		os.Exit(1)
	}
	subscription := "null"
	if sum.SubscriptionType != nil {
		subscription = *sum.SubscriptionType
	}
	fmt.Printf("wrote %s (subscription: %s, scopes: %s)\n",
		sum.Path, subscription, strings.Join(sum.Scopes, " "))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
