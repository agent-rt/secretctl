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

# ---------- configured but unreachable: still refuses ----------
# Approval is what lets a locked screen skip the biometric gate
# (keychain.Gate), so the gate must open only for a verdict that actually
# verified. Merely *having* push.json must not be enough — otherwise dropping a
# file into $SECRETCTL_HOME would be the whole 2FA bypass.
#
# 127.0.0.1:1 is https (http.zig refuses anything else before connecting) and
# refuses the connection immediately, so this stays fast and offline.
cat > "$SECRETCTL_HOME/push.json" <<'JSON'
{
  "worker_url": "https://127.0.0.1:1",
  "app_id": "app-e2e",
  "client_id": "client-e2e",
  "client_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "timeout_s": 5,
  "devices": [
    {"device_id": "dev-e2e", "sign_pubkey": "AAAA", "seal_pubkey": "AAAA",
     "fingerprint": "0000-0000-0000-0000", "label": "not a real phone"}
  ]
}
JSON
chmod 600 "$SECRETCTL_HOME/push.json"

set +e
out=$(locked list --json 2>&1); rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  ok "locked + unreachable approval service: refuses (rc=$rc)"
else
  bad "an unreachable approval service still unlocked" "$out"
fi
grep -q '"name":"TOK"' <<<"$out" \
  && bad "secret leaked without an approved verdict" "${out:0:160}" \
  || ok "locked + unreachable: no vault contents in the output"
grep -qi "master password" <<<"$out" \
  && bad "locked + configured: fell through to a passphrase prompt" "${out:0:160}" \
  || ok "locked + configured: still no passphrase prompt"

rm -f "$SECRETCTL_HOME/push.json"

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

# ---------- the key cache does not authorize `reveal` ----------
# The cache exists so a run of commands costs one prompt. `reveal` opts out of
# it (agent.CachePolicy), so a warm cache must not be enough to print plaintext.
#
# Asserted on the audit counter, not on reveal's output: `reveal` needs a
# terminal, script(1) supplies a pty, and a pty line-wraps — so grepping the
# value out of it is unreliable. `unlock.cached` is written exactly when the
# cache served an unlock, which is the fact under test and is wrap-proof.
#
# Falsified before being trusted: with reveal switched to `.allow`, this fails.
export SECRETCTL_AGENT=1
LOG=~/Library/Logs/secretctl.log
# `grep -c` prints 0 AND exits 1 when there is no match, so a naive
# `grep -c ... || echo 0` emits "0\n0" and every [[ -gt ]] using it dies with a
# syntax error. Capture, then default only when grep printed nothing at all
# (missing file).
count_cached() {
  local n
  n=$(grep -c '"op":"unlock.cached"' "$LOG" 2>/dev/null || true)
  echo "${n:-0}"
}

sc list --json >/dev/null 2>&1 || true          # warm it
BEFORE=$(count_cached)
if out=$(SECRETCTL_FORCE_LOCKED=0 "$BIN" list --json 2>&1) \
   && grep -q '"name":"TOK"' <<<"$out" \
   && [[ "$(count_cached)" -gt "$BEFORE" ]]; then
  ok "cache: 'list' unlocks from the cache with no passphrase"
else
  bad "cache: 'list' did not use the cache, so the next assertion proves nothing" \
      "${out:0:120}"
fi

# reveal must not take that same warm key. It will fail at the passphrase prompt
# instead, which is fine and is the point — the prompt is downstream of the
# cache check, so reaching it at all means the cache was refused.
BEFORE=$(count_cached)
set +e
SECRETCTL_FORCE_LOCKED=0 script -q /dev/null "$BIN" reveal TOK >/dev/null 2>&1
set -e
if [[ "$(count_cached)" -eq "$BEFORE" ]]; then
  ok "cache: 'reveal' refuses the warm cache and needs fresh authorization"
else
  bad "cache: a warm cache authorized 'reveal'" "unlock.cached went $BEFORE -> $(count_cached)"
fi

"$BIN" agent stop >/dev/null 2>&1 || true
export SECRETCTL_AGENT=0

# ---------- commands that need no unlock are untouched ----------
if SECRETCTL_FORCE_LOCKED=1 "$BIN" --version >/dev/null 2>&1; then
  ok "locked: --version still works (no unlock needed)"
else
  bad "--version broke while locked"
fi

if [[ $FAILED -ne 0 ]]; then echo; echo "LOCKSTATE E2E FAILED"; exit 1; fi
echo
echo "ALL LOCKSTATE E2E TESTS PASSED"
