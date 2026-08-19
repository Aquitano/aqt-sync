---
name: verify
description: Build and drive aqt CLI + server end-to-end for verification
---

# Verifying aqt changes end-to-end

Build both binaries (Go, no special setup):

```bash
go build -o "$SCRATCH/bin/aqt" ./cmd/aqt
go build -o "$SCRATCH/bin/aqt-server" ./cmd/aqt-server
```

Run a throwaway server:

```bash
AQT_DATA_DIR="$SCRATCH/srv-data" AQT_ADDR=127.0.0.1:18080 "$SCRATCH/bin/aqt-server" &
curl -s http://127.0.0.1:18080/healthz   # {"status":"ok"}
```

Drive the CLI as distinct users by switching HOME/XDG_CONFIG_HOME to per-user temp
dirs. Always set `AQT_NO_KEYCHAIN=1` (headless) and point `AQT_NODE_CACHE_DIR` into
the temp dir so the real user cache is untouched.

Scripted signup (prompts read stdin when it is not a tty; `--kdf-preset interactive`
keeps Argon2id calibration fast):

```bash
printf 'passphrase\n' | aqt --server http://127.0.0.1:18080 login \
  --email x@example.com --kdf-preset interactive
```

Gotchas:
- Files >= 8 MiB (streamThreshold) push through the streamed chunk/pack path;
  smaller files seal inline. Use >= 12 MiB to exercise streaming, >= 40 MiB for an
  indirect chunk list (>128 chunks).
- A link holder needs no login: `aqt pull '<url>#k...'` works from a fresh HOME
  (quote the URL — the fragment).
- Tracked folder: `aqt init . && aqt sync .`; the resource id is in `.aqt/state.json`.
