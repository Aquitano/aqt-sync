#!/bin/sh
# Install the aqt client (and optionally aqt-server) from a published GitHub release.
#
# The signed update manifest is the source of truth for what to download: it names
# the archive for this platform and carries its sha256, so this script never guesses
# a filename or trusts a length. Full signature verification happens on every later
# `aqt update`, which checks the manifest against keys compiled into the binary.
#
#   curl -fsSL https://aqt-sync.vercel.app/install.sh | sh
#   curl -fsSL https://aqt-sync.vercel.app/install.sh | sh -s -- --server
#
# Environment:
#   AQT_INSTALL_DIR   where to put the binaries (default ~/.local/bin)
#   AQT_VERSION       install this tag instead of the latest release
#   AQT_REPO          source repository (default Aquitano/aqt-sync)

# -f because the manifest fields are read through unquoted word splitting below; a
# filename or URL must never be expanded as a glob.
set -euf

repo="${AQT_REPO:-Aquitano/aqt-sync}"
install_dir="${AQT_INSTALL_DIR:-$HOME/.local/bin}"
version="${AQT_VERSION:-}"
want_server=0

for arg in "$@"; do
	case "$arg" in
	--server) want_server=1 ;;
	--dir=*) install_dir="${arg#--dir=}" ;;
	--version=*) version="${arg#--version=}" ;;
	-h | --help)
		cat <<'USAGE'
install.sh — install the aqt client from a published GitHub release

  --server           also install aqt-server
  --dir=PATH         install location (default ~/.local/bin)
  --version=TAG      install a specific release instead of the latest

Environment: AQT_INSTALL_DIR, AQT_VERSION, AQT_REPO
USAGE
		exit 0
		;;
	*)
		echo "install.sh: unknown option $arg" >&2
		exit 2
		;;
	esac
done

die() {
	echo "install.sh: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

need uname
need tar
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1"; }
	fetch_to() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO- "$1"; }
	fetch_to() { wget -qO "$2" "$1"; }
else
	die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die "sha256sum or shasum is required to verify a download"
fi

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported OS $(uname -s); build from source with 'make build'" ;;
esac

case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m); build from source with 'make build'" ;;
esac

if [ -n "$version" ]; then
	base="https://github.com/$repo/releases/download/$version"
else
	# GitHub's "latest" is the newest non-prerelease, which is the stable channel.
	base="https://github.com/$repo/releases/latest/download"
fi

manifest="$(fetch "$base/aqt-update.json")" || die "could not read the release manifest from $base"

# One awk pass over the manifest's artifact list: match the object whose os and arch
# are ours, then print the fields we need. Avoids a jq dependency.
read_artifact() {
	printf '%s\n' "$manifest" | awk -v os="$os" -v arch="$arch" '
		/"os"/     { gsub(/[",]/, ""); o = $2 }
		/"arch"/   { gsub(/[",]/, ""); a = $2 }
		/"name"/   { gsub(/[",]/, ""); n = $2 }
		/"size"/   { gsub(/[",]/, ""); s = $2 }
		/"sha256"/ { gsub(/[",]/, ""); h = $2 }
		/"url"/    { gsub(/[",]/, ""); u = $2
		             if (o == os && a == arch) { print n; print s; print h; print u; exit } }
	'
}

set -- $(read_artifact)
[ "$#" -eq 4 ] || die "the release publishes no archive for ${os}/${arch}"
asset_name="$1" asset_size="$2" asset_sha="$3" asset_url="$4"

version_label="$(printf '%s\n' "$manifest" | awk '/"version"/ { gsub(/[",]/, ""); print $2; exit }')"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "downloading aqt ${version_label} for ${os}/${arch}"
fetch_to "$asset_url" "$tmp/$asset_name" || die "download failed: $asset_url"

actual_size="$(wc -c <"$tmp/$asset_name" | tr -d ' ')"
[ "$actual_size" = "$asset_size" ] ||
	die "size mismatch: got $actual_size bytes, the manifest declares $asset_size"

actual_sha="$(sha256_of "$tmp/$asset_name")"
[ "$actual_sha" = "$asset_sha" ] ||
	die "checksum mismatch for $asset_name: got $actual_sha, want $asset_sha"

tar -xzf "$tmp/$asset_name" -C "$tmp"
mkdir -p "$install_dir"
install -m 0755 "$tmp/aqt" "$install_dir/aqt" 2>/dev/null ||
	{ cp "$tmp/aqt" "$install_dir/aqt" && chmod 0755 "$install_dir/aqt"; }
echo "installed $install_dir/aqt"

if [ "$want_server" -eq 1 ]; then
	server_name="$(printf '%s' "$asset_name" | sed 's/^aqt_/aqt-server_/')"
	server_url="$(printf '%s' "$asset_url" | sed "s|/$asset_name\$|/$server_name|")"
	# The server archive is not described by the client manifest, so its checksum
	# comes from the release's own checksums.txt rather than a signed source. An
	# unreadable or silent checksums.txt is a refusal, not a warning: a check that
	# quietly passes when it cannot run is worse than no check at all.
	fetch_to "$server_url" "$tmp/$server_name" || die "download failed: $server_url"
	checksums="$(fetch "${server_url%/*}/checksums.txt")" ||
		die "could not read checksums.txt; refusing to install an unverified $server_name"
	want="$(printf '%s\n' "$checksums" | awk -v n="$server_name" '$2 == n || $2 == "*" n { print $1; exit }')"
	[ -n "$want" ] || die "checksums.txt lists no entry for $server_name"
	got="$(sha256_of "$tmp/$server_name")"
	[ "$got" = "$want" ] || die "checksum mismatch for $server_name: got $got, want $want"
	tar -xzf "$tmp/$server_name" -C "$tmp"
	install -m 0755 "$tmp/aqt-server" "$install_dir/aqt-server" 2>/dev/null ||
		{ cp "$tmp/aqt-server" "$install_dir/aqt-server" && chmod 0755 "$install_dir/aqt-server"; }
	echo "installed $install_dir/aqt-server"
fi

case ":$PATH:" in
*":$install_dir:"*) ;;
*)
	echo
	echo "note: $install_dir is not on your PATH. Add it with:"
	echo "  export PATH=\"$install_dir:\$PATH\""
	;;
esac

echo
echo "next:"
echo "  aqt --server https://your-server login --email you@example.com"
echo "  aqt git setup    # only if you want encrypted Git remotes"
