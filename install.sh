#!/bin/sh
# clauth installer: download the latest release binary for this OS/arch and run it.
#
#   curl -fsSL https://raw.githubusercontent.com/mkmik/clauth/main/install.sh | sh
#
# Any extra args are passed through to clauth, e.g.:
#   ... | sh -s -- -port 4000
set -eu

REPO="mkmik/clauth"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "clauth: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
	linux | darwin) ;;
	*) echo "clauth: unsupported OS: $os" >&2; exit 1 ;;
esac

asset="clauth_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

echo "clauth: downloading ${url}" >&2
if ! curl -fsSL "$url" | tar -xz -C "$dir"; then
	echo "clauth: download or extract failed for ${asset}" >&2
	exit 1
fi

exec "$dir/clauth" "$@"
