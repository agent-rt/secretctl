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

# ---------- locked + TOTP ----------
# The offline approval channel. Codes are generated here by an INDEPENDENT
# implementation (python's hmac), which is the point: it proves the codes an
# authenticator app would produce are the codes this accepts. Verifying with
# secretctl's own generator would prove only self-consistency.
command -v python3 >/dev/null 2>&1 || { echo "  FAIL python3 needed to generate TOTP codes"; exit 1; }

SECRET=$(sc 2fa enroll 2>&1 | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
[[ -n "$SECRET" ]] && ok "2fa enroll emits an otpauth secret" \
                   || bad "enroll produced no secret"

totp_code() {
  python3 - "$SECRET" "${1:-0}" <<'PY'
import sys, hmac, hashlib, struct, base64, time
sec = base64.b32decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 8))
step = int(time.time()) // 30 + int(sys.argv[2])
mac = hmac.new(sec, struct.pack('>Q', step), hashlib.sha1).digest()
o = mac[19] & 0x0f
v = ((mac[o] & 0x7f) << 24) | (mac[o+1] << 16) | (mac[o+2] << 8) | mac[o+3]
print(f"{v % 10**6:06d}")
PY
}

# Wrong, malformed, and far-future codes must all be refused.
for bad_code in "000000" "12345" "abcdef" "$(totp_code 100)"; do
  set +e
  out=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_TOTP_FD=3 "$BIN" list --json 3<<<"$bad_code" 2>&1); rc=$?
  set -e
  if [[ $rc -ne 0 ]] && ! grep -q '"name":"TOK"' <<<"$out"; then
    ok "locked: refuses code '$bad_code'"
  else
    bad "locked: accepted a bad code '$bad_code'" "${out:0:120}"
  fi
done

# A correct, unspent code authorizes; this vault has no keychain protector, so
# the passphrase still has to produce the key afterwards. Two separate fds,
# which is also the assertion: the code channel and the passphrase channel must
# not collide (they did once, when both shared stdin).
CODE=$(totp_code)
set +e
out=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_TOTP_FD=3 SECRETCTL_PASSPHRASE_FD=4 \
      "$BIN" list --json 3<<<"$CODE" 4<<<"$PASS" 2>&1); rc=$?
set -e
grep -q '"name":"TOK"' <<<"$out" \
  && ok "locked: a valid TOTP code unlocks the vault" \
  || bad "locked: valid code did not unlock" "rc=$rc ${out:0:160}"

# The same output must be machine-parseable. Asserted by actually parsing it,
# on stdout alone — every other assertion here greps, which is why "authorized"
# being written to stdout survived into a release and was caught only by a real
# end-to-end run. One code, two assertions: a second unlock would need a second
# code, which is the behaviour under test elsewhere.
set +e
raw=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_TOTP_FD=3 SECRETCTL_PASSPHRASE_FD=4 \
      "$BIN" list --json 3<<<"$(totp_code 1)" 4<<<"$PASS" 2>/dev/null)
set -e
if python3 -c 'import sys,json; json.load(sys.stdin)' <<<"$raw" >/dev/null 2>&1; then
  ok "locked: --json stays parseable when a TOTP code authorized it"
else
  bad "locked: --json is polluted by progress text on stdout" "${raw:0:120}"
fi

# ...and only once. Replay is the failure mode that matters here: the code
# travels through whatever channel the operator used to hand it over.
set +e
out=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_TOTP_FD=3 SECRETCTL_PASSPHRASE_FD=4 \
      "$BIN" list --json 3<<<"$CODE" 4<<<"$PASS" 2>&1); rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "code-already-used" <<<"$out"; then
  ok "locked: the same code is refused as replay, with a distinct message"
else
  bad "locked: a spent code was accepted again" "rc=$rc ${out:0:160}"
fi

# ---------- the 120s authorization window ----------
# One code buys a window instead of a single command. That window is exactly
# what `authz.decide()` sitting above the key cache exists to prevent, reopened
# deliberately — so it has to be bounded, revocable, and visible.
#
# No keychain manipulation here: the window is a plain 0600 file, so this stays
# CI-safe. The guard that does need real keychain items lives in
# tests/local_totp_guard.sh, out of CI, after it hung the runner twice.
#
# Re-enrolled first, deliberately. The assertions above spend codes, and the
# replay ledger then only accepts last_used+1 — which is outside the ±1 skew
# window unless 30s have passed. A fresh seed has no spent steps. Without this
# the block failed to open a window at all, and its final assertion ("a spent
# code cannot open a second window") passed for the wrong reason: the code was
# already spent before it got there.
sc 2fa disable >/dev/null 2>&1
SECRET=$(sc 2fa enroll 2>&1 | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
[[ -n "$SECRET" ]] || bad "window: could not re-enroll for an isolated seed"

set +e
out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" list --json 2>&1); rc=$?
set -e
[[ $rc -ne 0 ]] && ok "window: closed by default — a bare command is refused" \
                || bad "window: something was already open" "${out:0:100}"

out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" 2fa auth "$(totp_code)" 2>&1 || true)
grep -q "authorized for" <<<"$out" \
  && ok "window: 2fa auth opens it" \
  || bad "window: 2fa auth did not open one" "${out:0:120}"

set +e
out=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_PASSPHRASE_FD=4 "$BIN" list --json 4<<<"$PASS" 2>/dev/null); rc=$?
set -e
grep -q '"name":"TOK"' <<<"$out" \
  && ok "window: a locked command needs no code while it is open" \
  || bad "window: open window did not authorize" "rc=$rc ${out:0:120}"

grep -q "window OPEN" <<<"$(sc 2fa status 2>&1 || true)" \
  && ok "window: status shows it open, with time left" \
  || bad "window: status does not report it"

sc 2fa revoke >/dev/null 2>&1
set +e
out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" list --json 2>&1); rc=$?
set -e
[[ $rc -ne 0 ]] && ok "window: revoke closes it immediately" \
                || bad "window: still open after revoke" "${out:0:100}"

# An expired window must close on its own. Written directly rather than waited
# out: the deadline is the file's whole content, so a past value exercises the
# same branch as 120s of patience. This is the assertion that makes the bound
# real rather than nominal.
out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" 2fa auth "$(totp_code 1)" 2>&1 || true)
if grep -q "authorized for" <<<"$out"; then
  echo "1" > "$SECRETCTL_HOME/totp.window"    # deadline in 1970
  set +e
  out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" list --json 2>&1); rc=$?
  set -e
  [[ $rc -ne 0 ]] && ok "window: an expired deadline stops authorizing" \
                  || bad "window: expired window still authorized" "${out:0:100}"
  grep -q "window closed" <<<"$(sc 2fa status 2>&1 || true)" \
    && ok "window: status reports an expired one as closed" \
    || bad "window: status still calls an expired window open"
else
  bad "window: could not open one to expire" "${out:0:100}"
fi
sc 2fa revoke >/dev/null 2>&1

# The code that opened a window is spent like any other — a window must not be
# a way to reuse one.
out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" 2fa auth "$(totp_code)" 2>&1 || true)
grep -q "code-already-used" <<<"$out" \
  && ok "window: the opening code is still single-use" \
  || bad "window: a spent code opened a second window" "${out:0:120}"
sc 2fa revoke >/dev/null 2>&1

# Disabling puts it back to refusing outright.
sc 2fa disable >/dev/null 2>&1
set +e
out=$(SECRETCTL_FORCE_LOCKED=1 SECRETCTL_TOTP_FD=3 "$BIN" list --json 3<<<"$(totp_code)" 2>&1); rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q "2fa enroll" <<<"$out" \
  && ok "locked: after disable, refuses and says how to re-enable" \
  || bad "locked: still accepted a code after disable" "${out:0:160}"

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
