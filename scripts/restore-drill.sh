#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# restore-drill.sh — prove a full backup -> restore cycle end to end.
#
# It builds aqt + aqt-server, runs a real server, pushes a realistic tree
# (nested dirs, a binary, an executable, a Unicode name, a tracked .git), takes a
# cold backup of the server data dir, stands a fresh server up from that backup,
# recovers the account on a clean client config from just the email + passphrase,
# clones the folder, and diffs the restored tree against the original. Any
# difference is a failure. This is the operator-facing twin of the in-process
# TestFullBackupRestoreDrill.
#
# Usage:  scripts/restore-drill.sh
# Requires: go, git, and a POSIX shell with `diff`. Uses only loopback HTTP, so no TLS
# or certificates are needed for the drill.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/aqt-restore-drill.XXXXXX")"
EMAIL="restore-drill-$$@example.invalid"
PASS="restore-drill-passphrase-$$"

# The OS keychain is bypassed so the drill never prompts and never touches a
# developer's real secret store; the session falls back to a machine-bound key.
export AQT_NO_KEYCHAIN=1

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

SERVER_PID=""
SERVER_URL=""
cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

log "building aqt and aqt-server"
mkdir -p "$WORK/bin"
( cd "$REPO" && go build -o "$WORK/bin/aqt" ./cmd/aqt )
( cd "$REPO" && go build -o "$WORK/bin/aqt-server" ./cmd/aqt-server )
# Git resolves aqt:: through this link into the same binary; see cmd/aqt/githelper.go.
ln -sf aqt "$WORK/bin/git-remote-aqt"
AQT="$WORK/bin/aqt"
SERVER="$WORK/bin/aqt-server"
export PATH="$WORK/bin:$PATH"

# start_server DATA_DIR LOG_FILE sets SERVER_PID and SERVER_URL in this shell so
# shutdown can wait for the server before copying or removing its data directory.
# It reads the ephemeral port from the log. Background jobs are disabled.
start_server() {
	local datadir="$1" logf="$2"
	AQT_DATA_DIR="$datadir" AQT_ADDR="127.0.0.1:0" \
		AQT_SNAPSHOT_INTERVAL=0 AQT_GC_INTERVAL=0 \
		"$SERVER" >"$logf" 2>&1 &
	SERVER_PID=$!
	local addr=""
	for _ in $(seq 1 100); do
		addr="$(sed -n 's/.*listening on \([0-9.]*:[0-9]*\).*/\1/p' "$logf" | head -1)"
		[ -n "$addr" ] && break
		kill -0 "$SERVER_PID" 2>/dev/null || { cat "$logf" >&2; fail "server exited before it started listening"; }
		sleep 0.1
	done
	[ -n "$addr" ] || { cat "$logf" >&2; fail "server did not report a listen address"; }
	SERVER_URL="http://$addr"
}

# wait_health polls /livez until the server answers (best effort: skipped if curl
# is absent, since the listen address already implies the socket is bound).
wait_health() {
	command -v curl >/dev/null 2>&1 || return 0
	for _ in $(seq 1 50); do
		curl -fsS "$1/livez" >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	fail "server health check never passed at $1/livez"
}

# build_tree writes a spread of file shapes a real backup must survive.
build_tree() {
	local root="$1"
	mkdir -p "$root/notes" "$root/bin" "$root/assets" "$root/data"
	printf '# project\n\nnotes and things\n' > "$root/README.md"
	printf -- '- [ ] buy milk\n- [ ] restore drill\n' > "$root/notes/todo.md"
	printf 'unicode body: cafe latte\n' > "$root/data/café.txt"
	: > "$root/empty.txt"
	printf '#!/bin/sh\necho hi\n' > "$root/bin/run.sh"; chmod 0755 "$root/bin/run.sh"
	# A multi-chunk binary, to exercise pack storage.
	dd if=/dev/urandom of="$root/assets/blob.bin" bs=1048576 count=5 status=none

	# A tracked git repo (the Brain-vault shape): opaque files re-included with !.git/.
	mkdir -p "$root/.git/refs/heads" "$root/.git/objects/pack"
	printf 'ref: refs/heads/main\n' > "$root/.git/HEAD"
	printf '[core]\n\trepositoryformatversion = 0\n' > "$root/.git/config"
	printf '0123456789abcdef0123456789abcdef01234567\n' > "$root/.git/refs/heads/main"
	dd if=/dev/urandom of="$root/.git/objects/pack/pack-drill.pack" bs=1024 count=4 status=none

	printf '!.git/\nnode_modules/\n' > "$root/.aqtignore"
	ln -s notes/todo.md "$root/link" 2>/dev/null || true
}

# --- Phase 1: machine A creates the account and pushes. ---
CONFIG_A="$WORK/config-a"
DATA_A="$WORK/data-a"; mkdir -p "$DATA_A"
export HOME="$CONFIG_A/home"
export XDG_CONFIG_HOME="$CONFIG_A"
mkdir -p "$HOME"

start_server "$DATA_A" "$WORK/server-a.log"
URL_A="$SERVER_URL"
log "server A listening at $URL_A"
wait_health "$URL_A"

log "creating account $EMAIL"
# signup prompts for the passphrase and then for a confirmation, so feed it twice.
printf '%s\n%s\n' "$PASS" "$PASS" | "$AQT" --server "$URL_A" signup --email "$EMAIL" \
	--kdf-time 2 --kdf-memory 64 --kdf-threads 1

ORIGIN="$WORK/origin"
build_tree "$ORIGIN"
log "init + push of the tree"
"$AQT" --server "$URL_A" init "$ORIGIN" </dev/null
"$AQT" --server "$URL_A" sync "$ORIGIN"

FOLDER_ID="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ORIGIN/.aqt/state.json" | head -1)"
[ -n "$FOLDER_ID" ] || fail "could not read the folder id from state.json"
log "folder id: $FOLDER_ID"

GIT_ORIGIN="$WORK/git-origin"
mkdir -p "$GIT_ORIGIN"
git -C "$GIT_ORIGIN" init -b main
git -C "$GIT_ORIGIN" config user.email "$EMAIL"
git -C "$GIT_ORIGIN" config user.name "AQT restore drill"
printf 'git remote restore drill\n' > "$GIT_ORIGIN/README.md"
mkdir -p "$GIT_ORIGIN/nested"
printf 'sealed history\n' > "$GIT_ORIGIN/nested/history.txt"
git -C "$GIT_ORIGIN" add README.md nested/history.txt
git -C "$GIT_ORIGIN" commit -m 'restore drill: initial history'
git -C "$GIT_ORIGIN" tag -a v1 -m 'restore drill tag'
log "creating and pushing an encrypted Git remote"
"$AQT" repo create restore-git
git -C "$GIT_ORIGIN" remote add origin aqt::restore-git
git -C "$GIT_ORIGIN" push -u origin main refs/tags/v1

# --- Phase 2: cold backup of the server data dir. ---
log "stopping server A and taking a cold backup of the data dir"
kill "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=""
BACKUP="$WORK/backup"
cp -a "$DATA_A" "$BACKUP"

# --- Phase 3: fresh server from a copy of the backup. ---
RESTORED_DATA="$WORK/data-restored"
cp -a "$BACKUP" "$RESTORED_DATA"
start_server "$RESTORED_DATA" "$WORK/server-b.log"
URL_B="$SERVER_URL"
log "restored server listening at $URL_B"
wait_health "$URL_B"

# --- Phase 4: clean machine recovers from email + passphrase alone. ---
CONFIG_B="$WORK/config-b"   # a fresh config dir == a clean machine
export HOME="$CONFIG_B/home"
export XDG_CONFIG_HOME="$CONFIG_B"
mkdir -p "$HOME"
log "recovering the account on a clean machine and cloning"
printf '%s\n' "$PASS" | "$AQT" --server "$URL_B" login --email "$EMAIL"

RESTORE="$WORK/restore"
"$AQT" --server "$URL_B" clone "$FOLDER_ID" "$RESTORE"

GIT_RESTORE="$WORK/git-restore"
git clone aqt::restore-git "$GIT_RESTORE"

# --- Phase 5: prove the restored tree matches the original. ---
log "diffing the restored tree against the original"
# diff -r compares file content but ignores permission bits and dereferences
# symlinks, so the mode and symlink-target checks below are explicit.
if ! diff -r -x .aqt "$ORIGIN" "$RESTORE"; then
	fail "restored tree differs from the original"
fi
[ -f "$RESTORE/.git/HEAD" ] || fail "the tracked .git directory was not restored"
[ -x "$RESTORE/bin/run.sh" ] || fail "exec bit was not restored (bin/run.sh is not executable)"
if [ -L "$ORIGIN/link" ]; then
	[ -L "$RESTORE/link" ] || fail "symlink was not restored as a symlink"
	[ "$(readlink "$RESTORE/link")" = "$(readlink "$ORIGIN/link")" ] || fail "symlink target differs"
fi

log "verifying the restored encrypted Git remote"
git -C "$GIT_RESTORE" fsck --full
git -C "$GIT_ORIGIN" for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags > "$WORK/git-origin.refs"
git -C "$GIT_RESTORE" for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags > "$WORK/git-restore.refs"
if ! diff -u "$WORK/git-origin.refs" "$WORK/git-restore.refs"; then
	fail "restored Git refs differ from the source"
fi

log "PASS: backup restore reproduced the folder and encrypted Git remote"
