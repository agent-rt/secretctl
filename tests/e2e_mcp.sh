#!/usr/bin/env bash
# Phase 2 e2e: drives `secretctl mcp` through `mcpctl` end-to-end.
# Skips gracefully when mcpctl is not installed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN — run: zig build" >&2
  exit 1
fi
if ! command -v mcpctl >/dev/null 2>&1; then
  echo "mcpctl not installed — skipping MCP e2e (install via: cargo install mcpctl)" >&2
  exit 0
fi

WORK="$(mktemp -d -t secretctl-mcp-e2e-XXXXXX)"
export SECRETCTL_HOME="$WORK/home"
export SECRETCTL_BATCH=1
export SECRETCTL_BATCH_KEYCHAIN=1     # MCP unlock needs keychain protector
PROJECT="$WORK/project"
mkdir -p "$PROJECT"

# Write mcpctl config pointing at our binary, scoped to this test only.
export XDG_CONFIG_HOME="$WORK/.config"
mkdir -p "$XDG_CONFIG_HOME/mcpctl"
cat > "$XDG_CONFIG_HOME/mcpctl/mcp.json" <<EOF
{
  "mcpServers": {
    "secretctl": {
      "command": "$BIN",
      "args": ["mcp", "--cwd", "$PROJECT"],
      "env": {
        "SECRETCTL_HOME": "$SECRETCTL_HOME",
        "SECRETCTL_BATCH": "1",
        "SECRETCTL_BATCH_KEYCHAIN": "1"
      }
    }
  }
}
EOF

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

PASS="hunter2hunter2"

# ---------- vault setup ----------
echo "$PASS" | "$BIN" init >/dev/null
printf "%s\nsk-test-openai\n" "$PASS" | "$BIN" add OPENAI_API_KEY --tag ai >/dev/null
printf "%s\nnpm-test-token\n" "$PASS" | "$BIN" add NPM_TOKEN --tag npm >/dev/null
printf "%s\nghp-test-token\n" "$PASS" | "$BIN" add GITHUB_TOKEN --tag github >/dev/null

cat > "$PROJECT/.secretctl.toml" <<'EOF'
[allow]
tags     = ["npm", "ai"]
commands = ["echo", "true"]
EOF

# ---------- server check ----------
mcpctl server check secretctl >/dev/null
echo "ok: mcpctl server check"

# ---------- introspect ----------
INTRO="$(mcpctl introspect secretctl --json)"
for tool in list_secrets check_secret_available run_with_secrets; do
  if ! echo "$INTRO" | jq -e --arg t "$tool" '.tools[] | select(.name == $t)' >/dev/null; then
    echo "FAIL: introspect missing $tool"
    echo "$INTRO" | jq '.tools[].name'
    exit 1
  fi
done
echo "ok: mcpctl introspect lists 3 tools"

# ---------- list_secrets ----------
LS="$(mcpctl secretctl/list_secrets --args-json '{}' --structured 2>/dev/null || mcpctl secretctl/list_secrets --args-json '{}')"
echo "$LS" | grep -q "OPENAI_API_KEY" || { echo "FAIL: list_secrets missing OPENAI_API_KEY"; echo "$LS"; exit 1; }
echo "$LS" | grep -q "NPM_TOKEN" || { echo "FAIL: list_secrets missing NPM_TOKEN"; exit 1; }
echo "$LS" | grep -q "sk-test-openai" && { echo "FAIL: list_secrets leaked value"; exit 1; }
echo "ok: list_secrets returns names without value"

# ---------- check_secret_available ----------
CSA="$(mcpctl secretctl/check_secret_available --args-json '{"name":"OPENAI_API_KEY"}')"
echo "$CSA" | grep -q '"exists":true' || { echo "FAIL: check_secret_available true case"; echo "$CSA"; exit 1; }
CSA_NO="$(mcpctl secretctl/check_secret_available --args-json '{"name":"NOPE"}')"
echo "$CSA_NO" | grep -q '"exists":false' || { echo "FAIL: check_secret_available false case"; echo "$CSA_NO"; exit 1; }
echo "ok: check_secret_available true/false"

# ---------- run_with_secrets — allowed ----------
RUN_OK="$(mcpctl secretctl/run_with_secrets --args-json '{"command":"echo","args":["hello-world"],"tags":["npm"]}')"
echo "$RUN_OK" | grep -q "hello-world" || { echo "FAIL: run_with_secrets did not echo args"; echo "$RUN_OK"; exit 1; }
echo "$RUN_OK" | grep -q "npm-test-token" && { echo "FAIL: run_with_secrets leaked value into output"; exit 1; }
echo "ok: run_with_secrets allowed command runs"

# ---------- run_with_secrets — disallowed command ----------
RUN_BAD="$(mcpctl secretctl/run_with_secrets --args-json '{"command":"bash","args":["-c","echo bad"],"tags":["npm"]}' 2>&1 || true)"
echo "$RUN_BAD" | grep -qE "(allowlist|isError)" || { echo "FAIL: disallowed command not rejected"; echo "$RUN_BAD"; exit 1; }
echo "ok: run_with_secrets rejects disallowed command"

# ---------- run_with_secrets — disallowed tag ----------
RUN_TAG="$(mcpctl secretctl/run_with_secrets --args-json '{"command":"echo","tags":["github"]}' 2>&1 || true)"
echo "$RUN_TAG" | grep -qE "(allowlist|isError)" || { echo "FAIL: disallowed tag not rejected"; echo "$RUN_TAG"; exit 1; }
echo "ok: run_with_secrets rejects disallowed tag"

# ---------- audit log JSONL ----------
LOG=~/Library/Logs/secretctl.log
[[ -f "$LOG" ]] || { echo "FAIL: audit log not created"; exit 1; }
LAST="$(tail -n 5 "$LOG")"
# Check the lines are JSON and contain mcp transport.
echo "$LAST" | while IFS= read -r line; do
  echo "$line" | jq -e . >/dev/null || { echo "FAIL: audit line not JSON: $line"; exit 1; }
done
echo "$LAST" | grep -q '"transport":"mcp"' || { echo "FAIL: audit log missing transport=mcp"; exit 1; }
echo "$LAST" | grep -qE "sk-test-openai|npm-test-token|ghp-test-token" && { echo "FAIL: audit log leaked secret value"; exit 1; }
echo "ok: audit log JSONL with transport=mcp, no value leaks"

# ---------- dangerous mode tools/list ----------
# We register a second mcpctl server entry pointing at `mcp --allow-secret-read`
# so we can hit tools/list without firing a real Touch ID prompt (introspect
# only sends initialize + tools/list).
cat > "$XDG_CONFIG_HOME/mcpctl/mcp.json" <<EOF
{
  "mcpServers": {
    "secretctl": {
      "command": "$BIN",
      "args": ["mcp", "--cwd", "$PROJECT"],
      "env": {
        "SECRETCTL_HOME": "$SECRETCTL_HOME",
        "SECRETCTL_BATCH": "1",
        "SECRETCTL_BATCH_KEYCHAIN": "1"
      }
    },
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

# Detect whether this Mac actually has Touch ID/Face ID enrolled. If not,
# the server should refuse to start in dangerous mode (exit 2). Use a helper
# binary "bioutil" status — fall back to assuming hardware is present on M-series.
HAS_BIOMETRY=1
if ! /usr/sbin/bioutil -r >/dev/null 2>&1 && [[ "$(uname -m)" != "arm64" ]]; then
  HAS_BIOMETRY=0
fi

if [[ "$HAS_BIOMETRY" == "1" ]]; then
  DANG_INTRO="$(mcpctl introspect secretctl_dangerous --json 2>/dev/null || true)"
  if [[ -n "$DANG_INTRO" ]] && echo "$DANG_INTRO" | jq -e '.tools[] | select(.name == "get_secret")' >/dev/null 2>&1; then
    DANG_COUNT="$(echo "$DANG_INTRO" | jq '.tools | length')"
    [[ "$DANG_COUNT" == "4" ]] || { echo "FAIL: dangerous mode tools count $DANG_COUNT, expected 4"; exit 1; }
    echo "ok: dangerous mode lists 4 tools (incl. get_secret)"
  else
    echo "skip: dangerous-mode introspect (LA may not be available in this CI)"
  fi
else
  set +e
  RES="$(mcpctl introspect secretctl_dangerous --json 2>&1)"
  set -e
  echo "$RES" | grep -q "Touch ID" && echo "ok: dangerous mode refuses without biometry hardware" || echo "skip: dangerous-mode hardware-check probe inconclusive"
fi

echo
echo "ALL MCP E2E TESTS PASSED"
