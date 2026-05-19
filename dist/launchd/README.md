# Installing the agentworld daemon as a LaunchAgent

The daemon (`aw-mvp --daemon`) captures macOS telemetry, persists a graph snapshot to `~/Library/Application Support/agentworld/world.db` on every tick, and narrates the activity through a local Ollama model. As a LaunchAgent it:

- starts on login,
- restarts itself on crash,
- runs at background priority so it never competes with foreground work,
- logs stdout/stderr to `~/Library/Logs/agentworld/`.

## What you need

- `aw-mvp` built and installed somewhere stable. **`target/debug/aw-mvp` is not stable** — `cargo build` will overwrite it. Either:
  - `cargo install --path crates/aw-mvp` to drop a release-mode binary into `~/.cargo/bin/aw-mvp`, or
  - copy `target/release/aw-mvp` to `/usr/local/bin/aw-mvp` after `cargo build --release -p aw-mvp`.
- Ollama running locally (default `http://127.0.0.1:11434`) with the `gemma3:4b` model pulled.
- Full Disk Access granted to the binary if you want FSEvents to see protected paths (System Settings → Privacy & Security → Full Disk Access).

## Install

From the repo root:

```bash
# 1. Pick the binary path and home, fill in the template.
AW_MVP_BIN="$HOME/.cargo/bin/aw-mvp"   # or wherever you put it
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs/agentworld"

sed \
  -e "s|__AW_MVP_BIN__|$AW_MVP_BIN|g" \
  -e "s|__HOME__|$HOME|g" \
  dist/launchd/com.agentworld.daemon.plist.template \
  > "$HOME/Library/LaunchAgents/com.agentworld.daemon.plist"

# 2. Load it. `bootstrap` is the modern launchctl verb (macOS 10.10+).
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.agentworld.daemon.plist"
```

## Verify

```bash
launchctl print gui/$(id -u)/com.agentworld.daemon | head -20
tail -f "$HOME/Library/Logs/agentworld/daemon.err.log"
```

Within a few minutes you should see merge lines (`aw-mvp: merged into ... (nodes +X/Y, edges +A/B, trimmed Z)`) and the first narration paragraph in `daemon.out.log`.

## Stop / uninstall

```bash
launchctl bootout gui/$(id -u)/com.agentworld.daemon
rm "$HOME/Library/LaunchAgents/com.agentworld.daemon.plist"
# Optional: also remove logs and the store
rm -rf "$HOME/Library/Logs/agentworld"
rm -rf "$HOME/Library/Application Support/agentworld"
```

## Troubleshooting

- **Daemon flapping** (restart loop): check `daemon.err.log`. Common causes:
  - Ollama not running → narration fails each tick, but the daemon keeps capturing. Not a flap.
  - Binary path wrong → the plist's `ProgramArguments` references a missing executable; `launchctl` will report `Could not find specified service`.
  - Store path unwritable → run `aw-mvp --store-path /tmp/aw.db --daemon` interactively to isolate.
- **No FSEvents activity**: grant Full Disk Access to the binary; restart the daemon.
- **High disk use**: tune `--store-ttl` lower (e.g. `1800` for 30 min) to trim the in-memory graph more aggressively; the store growth is still bounded by distinct entities.
