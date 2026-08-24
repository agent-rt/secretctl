#!/usr/bin/env bash
# e2e: the authorization split. A locked screen must not reach the keychain or
# the agent cache — it must refuse, and say what is missing.
#
# SECRETCTL_FORCE_LOCKED exists for exactly this: without it none of these
# paths are testable in CI or by hand, because the alternative is locking the
# developer's screen and losing the terminal.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN — run: zig build" >&2
  exit 1
fi

WORK="$(mktemp -d -t secretctl-lock-e2e-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export SECRETCTL_HOME="$WORK/home"
export SECRETCTL_BATCH=1
unset VISUAL
PASS="hunter2hunter2"

# Explicit on both sides: the real screen state must never decide the result.
sc()     { SECRETCTL_FORCE_LOCKED=0 SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }
locked() { SECRETCTL_FORCE_LOCKED=1 SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }

FAILED=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; [[ -n "${2:-}" ]] && echo "         $2"; FAILED=1; }

# Agent off: correctness must not depend on it, and leaving it on would let a
# warm cache mask the very window this gate exists to close.
export SECRETCTL_AGENT=0

sc init >/dev/null
printf 'sk-real-value\n' | sc add TOK --tag t >/dev/null
ok "vault created and a secret added while unlocked"

# ---------- unlocked: unchanged ----------
if out=$(sc list --json 2>&1) && grep -q '"name":"TOK"' <<<"$out"; then
  ok "unlocked: list works exactly as before"
else
  bad "unlocked list" "$out"
fi

# ---------- locked: refuses, and says which thing is missing ----------
set +e
out=$(locked list --json 2>&1); rc=$?
set -e
[[ $rc -ne 0 ]] && ok "locked: list refuses (rc=$rc)" \
                || bad "locked list succeeded" "$out"
grep -q "screen is locked" <<<"$out" \
  && ok "locked: says the screen is locked" \
  || bad "no lock reason in message" "$out"
grep -q "secretctl 2fa enroll" <<<"$out" \
  && ok "locked: names the command that would fix it" \
  || bad "no actionable hint" "$out"
# It must not fall through to a passphrase prompt: nobody is there to type one.
grep -qi "master password" <<<"$out" \
  && bad "locked: fell through to a passphrase prompt" "$out" \
  || ok "locked: no passphrase prompt"

# ---------- locked: every unlocking command, not just list ----------
for cmd in "list --json" "reveal TOK" "exec --tag t -- env"; do
  set +e
  out=$(locked $cmd 2>&1); rc=$?
  set -e
  if [[ $rc -ne 0 ]] && grep -q "screen is locked" <<<"$out"; then
    ok "locked: '$cmd' refuses at the authorization gate"
  else
    bad "locked: '$cmd' did not refuse at the gate" "rc=$rc ${out:0:120}"
  fi
done

# ---------- the gate sits above the agent cache ----------
# Warm the cache while unlocked, then lock. A gate placed below the cache would
# serve the cached key and require no approval — the window this closes.
export SECRETCTL_AGENT=1
sc list --json >/dev/null 2>&1 || true
set +e
out=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_AGENT=1 SECRETCTL_PASSPHRASE_FD=3 \
      "$BIN" list --json 3<<<"$PASS" 2>&1); rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "screen is locked" <<<"$out"; then
  ok "locked: refuses even with a warm agent cache"
else
  bad "a warm cache bypassed the gate" "rc=$rc ${out:0:160}"
fi
"$BIN" agent stop >/dev/null 2>&1 || true
export SECRETCTL_AGENT=0

# ---------- the override fails closed ----------
set +e
out=$(SECRETCTL_FORCE_LOCKED=yes SECRETCTL_PASSPHRASE_FD=3 "$BIN" list --json 3<<<"$PASS" 2>&1); rc=$?
set -e
[[ $rc -ne 0 ]] && ok "override: any non-zero value means locked" \
                || bad "override with 'yes' was treated as unlocked" "$out"

set +e
out=$(SECRETCTL_FORCE_LOCKED=0 SECRETCTL_PASSPHRASE_FD=3 "$BIN" list --json 3<<<"$PASS" 2>&1); rc=$?
set -e
[[ $rc -eq 0 ]] && ok "override: 0 means unlocked" \
                || bad "override with 0 did not behave as unlocked" "$out"

# ---------- commands that need no unlock are untouched ----------
if SECRETCTL_FORCE_LOCKED=1 "$BIN" --version >/dev/null 2>&1; then
  ok "locked: --version still works (no unlock needed)"
else
  bad "--version broke while locked"
fi

if [[ $FAILED -ne 0 ]]; then echo; echo "LOCKSTATE E2E FAILED"; exit 1; fi
echo
echo "ALL LOCKSTATE E2E TESTS PASSED"
