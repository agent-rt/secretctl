#!/usr/bin/env bash
# e2e: the MCP server must never read fd 0 for user input.
#
# e2e_mcp.sh cannot cover this: it always sets SECRETCTL_BATCH_KEYCHAIN=1, so a
# keychain protector always exists, the unlock always succeeds, and the
# passphrase-fallback path is never entered. Here the vault is passphrase-ONLY,
# which forces the MCP unlock down that path.
#
# Before the fix, the fallback called tty.readPassword, which reads fd 0 — the
# JSON-RPC transport. With SECRETCTL_BATCH=1 (which e2e_mcp.sh also sets) it
# consumed the *next request frame* as the master password: the third request
# below never got a response, and the second failed with AuthenticationFailed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN — run: zig build" >&2
  exit 1
fi

WORK="$(mktemp -d -t secretctl-mcp-locked-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export SECRETCTL_HOME="$WORK/home"
PROJECT="$WORK/project"
mkdir -p "$PROJECT"
PASS="hunter2hunter2"

# Passphrase on its own fd — never stdin. See tty.passphraseFd.
sc() { SECRETCTL_BATCH=1 SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }

# SECRETCTL_BATCH without SECRETCTL_BATCH_KEYCHAIN => passphrase-only vault, so
# the MCP server's keychain unlock cannot succeed. Agent off for hermeticity
# only: the passphrase has its own fd, so unlock state no longer shifts stdin.
export SECRETCTL_AGENT=0
sc init >/dev/null
printf 'sk-test-openai\n' | sc add OPENAI_API_KEY --tag ai >/dev/null

cat > "$PROJECT/.secretctl.toml" <<'EOF'
[allow]
tags = ["ai"]
EOF

OUT="$WORK/out.jsonl"
ERR="$WORK/err.txt"

# Three frames on one stream. Frame 3 exists purely to detect frame-eating.
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}'
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}'
} | SECRETCTL_BATCH=1 "$BIN" mcp --cwd "$PROJECT" >"$OUT" 2>"$ERR" || true

# 1. The protocol must survive: every frame answered, frame 3 in particular.
grep -q '"id":1' "$OUT" || { echo "FAIL: no response to frame 1"; exit 1; }
grep -q '"id":2' "$OUT" || { echo "FAIL: no response to frame 2"; exit 1; }
grep -q '"id":3' "$OUT" || { echo "FAIL: frame 3 got no response — the server ate it as input"; exit 1; }
echo "ok: mcp answers every frame with a locked vault (no frame consumed as input)"

# 2. No prompt may be written, and the error must be actionable rather than a
#    bare AuthenticationFailed from a JSON frame used as a password.
# The literal old prompt, not just the words "master password" — the current
# diagnostic legitimately mentions them while explaining why it cannot ask.
grep -q "master password (mcp unlock)" "$ERR" && { echo "FAIL: mcp prompted for a password"; exit 1; }
grep -q "vault is locked" "$OUT" || { echo "FAIL: locked vault did not report an actionable error"; exit 1; }
grep -q "AuthenticationFailed" "$OUT" && { echo "FAIL: frame was used as a password"; exit 1; }
echo "ok: locked vault reports an actionable error, no prompt on stderr"

# 3. SECRETCTL_BATCH must not turn fd 0 into a secret-value source under MCP.
grep -q "jsonrpc" <(grep -o 'jsonrpc' "$OUT" | head -1) || { echo "FAIL: no JSON-RPC output at all"; exit 1; }
echo "ok: SECRETCTL_BATCH did not divert the JSON-RPC stream"

echo "PASS: tests/e2e_mcp_locked.sh"
