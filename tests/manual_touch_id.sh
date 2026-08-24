#!/usr/bin/env bash
# Manual Phase 3 verification — requires Touch ID hardware AND user
# interaction (fingerprint scans). NOT part of automated CI.
#
# Walks through:
#   1. Touch ID-gated unlock (`init --touch-id` then `list`)
#   2. cancelling the prompt, and the audit log afterwards
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
export SECRETCTL_AGENT=0
export SECRETCTL_BATCH_KEYCHAIN=1

cleanup() {
  rm -rf "$WORK"
  security delete-generic-password -s secretctl >/dev/null 2>&1 || true
}
trap cleanup EXIT

PASS="touch-id-test-pass"

# Passphrase on its own fd — never stdin. See tty.passphraseFd.
sc() { SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }

echo "===== 1. init --touch-id ====="
sc init --touch-id
printf 'sk-touch-id-secret\n' | sc add OPENAI_API_KEY --tag ai >/dev/null
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

echo "===== 4. audit log inspection ====="
LOG=~/Library/Logs/secretctl.log
echo "Last 5 audit lines:"
tail -n 5 "$LOG" | jq -c .

if tail -n 20 "$LOG" | grep -qE 'sk-touch-id-secret'; then
  echo "FAIL: audit log leaked secret value"
  exit 1
fi
echo "ok: no value leaks in audit log"

echo
echo "Manual Touch ID verification complete. Inspect outputs above for correctness."
