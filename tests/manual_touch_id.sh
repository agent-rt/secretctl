#!/usr/bin/env bash
# Manual Phase 3 verification — requires Touch ID hardware AND user
# interaction (fingerprint scans). NOT part of automated CI.
#
# Walks through:
#   1. Touch ID-gated unlock (`init --touch-id` then `list`)
#   2. MCP dangerous mode `get_secret` via mcpctl (per-call Touch ID)
#
# Run from a real terminal (interactive). Cleanup on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN — run: zig build" >&2
  exit 1
fi

if [[ ! -t 0 ]] || [[ ! -t 1 ]]; then
  echo "this script needs an interactive terminal (Touch ID prompts cannot be auto-answered)" >&2
  exit 2
fi

WORK="$(mktemp -d -t secretctl-touchid-XXXXXX)"
export SECRETCTL_HOME="$WORK/home"
export SECRETCTL_BATCH=1
export SECRETCTL_BATCH_KEYCHAIN=1

cleanup() {
  rm -rf "$WORK"
  security delete-generic-password -s secretctl >/dev/null 2>&1 || true
}
trap cleanup EXIT

PASS="touch-id-test-pass"

echo "===== 1. init --touch-id ====="
echo "$PASS" | "$BIN" init --touch-id
printf "%s\nsk-touch-id-secret\n" "$PASS" | "$BIN" add OPENAI_API_KEY --tag ai >/dev/null
echo "Vault created with Touch ID protector."
echo

echo "===== 2. list — should prompt for Touch ID ====="
echo "Place finger on Touch ID sensor when prompted."
"$BIN" list --json
echo "If list output appeared, Touch ID unlock works ✓"
echo

echo "===== 3. cancel scenario (press Esc / cancel button on next prompt) ====="
echo "When the prompt appears, click Cancel. Should fall back to password."
set +e
"$BIN" list --json
EC=$?
set -e
echo "exit=$EC (expected 1 since password fallback also fails in batch mode)"
echo

if ! command -v mcpctl >/dev/null 2>&1; then
  echo "mcpctl not installed — skipping MCP dangerous mode tests"
  exit 0
fi

echo "===== 4. MCP dangerous mode startup ====="
PROJECT="$WORK/project"
mkdir -p "$PROJECT"
cat > "$PROJECT/.secretctl.toml" <<'EOF'
[allow]
tags = ["ai"]
commands = ["echo"]
EOF

export XDG_CONFIG_HOME="$WORK/.config"
mkdir -p "$XDG_CONFIG_HOME/mcpctl"
cat > "$XDG_CONFIG_HOME/mcpctl/mcp.json" <<EOF
{
  "mcpServers": {
    "secretctl_dangerous": {
      "command": "$BIN",
      "args": ["mcp", "--allow-secret-read", "--cwd", "$PROJECT"],
      "env": {
        "SECRETCTL_HOME": "$SECRETCTL_HOME",
        "SECRETCTL_BATCH": "1",
        "SECRETCTL_BATCH_KEYCHAIN": "1"
      }
    }
  }
}
EOF

echo "Listing tools (should show 4: + get_secret)"
mcpctl introspect secretctl_dangerous --json 2>/dev/null | jq -r '.tools[].name'
echo
echo "===== 5. get_secret — Touch ID prompt expected ====="
echo "Place finger when prompted; should return value."
mcpctl secretctl_dangerous/get_secret --args-json '{"name":"OPENAI_API_KEY"}'
echo

echo "===== 6. get_secret cancel — press Cancel on next Touch ID prompt ====="
mcpctl secretctl_dangerous/get_secret --args-json '{"name":"OPENAI_API_KEY"}' || true
echo "(Should be isError: true with biometric authentication declined)"
echo

echo "===== 7. audit log inspection ====="
LOG=~/Library/Logs/secretctl.log
echo "Last 5 audit lines:"
tail -n 5 "$LOG" | jq -c .

if tail -n 20 "$LOG" | grep -qE 'sk-touch-id-secret'; then
  echo "FAIL: audit log leaked secret value"
  exit 1
fi
echo "ok: no value leaks in audit log"

echo
echo "Manual Phase 3 verification complete. Inspect outputs above for correctness."
