# clauth

Log a remote/headless machine into **Claude Code** with your Claude **Pro/Max
subscription**, from your own browser — no `claude auth login` prompt on the box.

`clauth` runs the exact OAuth2 + PKCE flow the Claude Code CLI uses, exchanges
the code, and writes `~/.claude/.credentials.json` in the precise shape the CLI
reads. After it runs, `claude auth status` on that machine reports a genuine
`"authMethod": "claude.ai"` subscription login.

Built for VMs (e.g. [exe.dev](https://exe.dev)) where the browser is never on
the same host: it serves a tiny one-page web app, prints the public URL to open,
and you paste back the code the sign-in shows you.

## Install

Run this on the VM:

```sh
curl -fsSL https://raw.githubusercontent.com/mkmik/clauth/main/install.sh | sh
```

## Quick start

The install line above downloads the right binary for the VM's OS/arch and starts
it. It prints a line like:

```
  clauth is ready. Open this URL in your browser to sign in to Claude Code:

      https://orca-cookie.exe.xyz:3456/
```

Open that URL, click **Open Claude sign in**, approve in your browser, and paste
the `code#state` string Claude shows you back into the page. Done — run `claude`.

Pass flags through the installer after `--`:

```sh
curl -fsSL https://raw.githubusercontent.com/mkmik/clauth/main/install.sh | sh -s -- -port 4000
```

## Why a fixed, unusual port

Login is infrequent — usually right after VM creation, occasionally on a VM
that's already serving something on the main port. `clauth` defaults to
**`:3456`** (memorable, rarely used) and only moves to a random free port if
3456 is taken — it prints whichever it landed on.

## The public URL

The printed URL is `https://<host>.<base-domain>:<port>/`. `clauth` derives the
host from the exe.dev metadata service (falling back to the OS hostname); a short
name gets `.exe.xyz` appended. Override any of it:

| flag / env | effect |
|---|---|
| `-port N` | preferred port (default 3456) |
| `-host ADDR` | bind address (default `0.0.0.0`) |
| `-public-host H` / `CLAUTH_PUBLIC_HOST` | force the hostname in the printed URL |
| `-base-domain D` / `CLAUTH_BASE_DOMAIN` | domain appended to a short hostname (default `exe.xyz`) |

## No web UI (pure CLI)

```sh
clauth -print-url                                   # prints authorize URL + verifier/state
# open it, approve, copy the code#state, then:
clauth -exchange 'CODE#STATE' -verifier <V> -state <S>
```

## Other flags

| flag | effect |
|---|---|
| `-console` | use the console (API-credits) authorize endpoint instead of the claude.ai subscription one |
| `-version` | print version |

Honors `CLAUDE_CONFIG_DIR` (default `~/.claude`). Uses the system trust store
(respects `SSL_CERT_FILE`) and standard `HTTPS_PROXY`.

## Protocol

Standard **OAuth2 Authorization Code + PKCE (S256)** against Anthropic's public
native client. Constants were verified against the shipped Claude Code binary.

| | value |
|---|---|
| `client_id` | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` |
| authorize (subscription) | `https://claude.com/cai/oauth/authorize` |
| token | `https://platform.claude.com/v1/oauth/token` |
| profile (subscription lookup) | `https://api.anthropic.com/api/oauth/profile` |
| redirect (paste flow) | `https://platform.claude.com/oauth/code/callback` |
| scopes | `org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload` |

Token exchange is a JSON `POST` to the token URL; the response's
`access_token` / `refresh_token` / `expires_in` are written under
`claudeAiOauth` (with `expiresAt` in epoch ms), and `subscriptionType` /
`rateLimitTier` are filled from the profile endpoint. The CLI auto-refreshes
using the stored refresh token, so a single login persists.

> **macOS note:** the native CLI stores credentials in the login Keychain and
> reads the file only as a fallback. `clauth` writes the file form; it is the
> canonical store on Linux (the intended target).

## Development

```sh
go test ./...
go build .
```

CI runs `gofmt`/`go vet`/`go test` on every push and PR. Every push to `main`
bumps the minor version tag and [goreleaser](https://goreleaser.com) publishes
the binaries — no binaries are committed to git.

Use it only to sign in with **your own** Anthropic account.
