#!/bin/sh
# Installs the newest release of best-peer for this machine: the archive is taken from GitHub, checked against the
# release's SHA256SUMS, and the binary put in ~/.local/bin (BEST_PEER_INSTALL_DIR chooses another place). Run it
# again to upgrade: the data folder (~/.best-peer: the event log, the credentials, the certificate) is not touched,
# and a peer still running keeps the old binary until it is restarted.
#
#   curl -fsSL https://raw.githubusercontent.com/behavioralstate/best-peer/main/install.sh | sh
#
# BEST_PEER_VERSION=0.0.12 pins a release instead of the newest.
set -eu

repo="behavioralstate/best-peer"
dir="${BEST_PEER_INSTALL_DIR:-$HOME/.local/bin}"
case "$dir" in /*) ;; *) dir="$PWD/$dir" ;; esac   # absolute before the cd into the temp folder below

os=$(uname -s)
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  arm64|aarch64) arch=aarch64 ;;
  *) echo "best-peer: no release for $arch; build it with: cargo install --git https://github.com/$repo best-peer" >&2; exit 1 ;;
esac
case "$os-$arch" in
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Darwin-aarch64) target=aarch64-apple-darwin ;;
  *) echo "best-peer: no release for $os on $arch yet (Linux x86_64 and macOS Apple silicon are built); build it with: cargo install --git https://github.com/$repo best-peer" >&2; exit 1 ;;
esac

if [ -n "${BEST_PEER_VERSION:-}" ]; then
  base="https://github.com/$repo/releases/download/v$BEST_PEER_VERSION"
  archive="best-peer-$BEST_PEER_VERSION-$target.tar.gz"
else
  base="https://github.com/$repo/releases/latest/download"
  archive="best-peer-$target.tar.gz"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $base/$archive"
curl -fsSL -o "$tmp/$archive" "$base/$archive" || {
  echo "best-peer: $base/$archive could not be downloaded; the releases are at https://github.com/$repo/releases" >&2
  exit 1
}
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || {
  echo "best-peer: $base/SHA256SUMS could not be downloaded; the releases are at https://github.com/$repo/releases" >&2
  exit 1
}
cd "$tmp"
expected=$(grep " \*\{0,1\}$archive\$" SHA256SUMS | awk '{print $1}')
[ -n "$expected" ] || { echo "best-peer: $archive is not in SHA256SUMS" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
[ "$expected" = "$actual" ] || { echo "best-peer: the checksum of $archive does not match SHA256SUMS" >&2; exit 1; }
tar xzf "$archive"
[ -f "best-peer-$target/best-peer" ] || {
  echo "best-peer: $archive does not hold best-peer-$target/best-peer: a release older than the layout this script knows; pin a newer one" >&2
  exit 1
}
mkdir -p "$dir"
install -m 0755 "best-peer-$target/best-peer" "$dir/best-peer"
version=$("$dir/best-peer" --version) || {
  echo "best-peer: $dir/best-peer is installed but does not run on this machine; the Linux build needs glibc 2.35 or newer (\`ldd --version\` says yours); build it here with: cargo install --git https://github.com/$repo best-peer" >&2
  exit 1
}
echo "Installed $version in $dir"
case ":$PATH:" in
  *":$dir:"*) echo "Next: best-peer (the README's 'Try it on your machine' says what to set first)" ;;
  *) echo "Add $dir to your PATH, then: best-peer (the README's 'Try it on your machine' says what to set first)" ;;
esac
