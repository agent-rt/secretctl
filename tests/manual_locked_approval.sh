#!/usr/bin/env bash
# Manual verification of the locked-screen path, on hardware, with a real phone.
# Not part of any automated suite: it needs a screen that is actually locked and
# a human tapping a notification. Everything below that line is covered by
# tests/e2e_lockstate.sh, which fakes the lock state via SECRETCTL_FORCE_LOCKED.
#
# What this proves that the automated suite cannot: that a real locked screen is
# detected (not the override), that the push arrives, and that after approval the
# Touch-ID-gated keychain protector actually yields the master key — the step
# that used to fail after 13 s (docs/2fa-push-approval.md §2.2b).
#
# It works on a THROWAWAY VAULT in its own $SECRETCTL_HOME, never ~/.secretctl.
# Two reasons, both learned the hard way:
#
#   * The keychain protector's ACL trusts one binary by path and signature. Run
#     this dev build against the real vault and the stale-ACL self-heal rewrites
#     the protector to trust ./zig-out/bin/secretctl, which breaks the Homebrew
#     one until `secretctl reinstall-keychain`.
#   * Cleanup deletes exactly this vault's keychain item, by account name
#     (hex of its master_key_id). Never `prune-keychain` — with a non-default
#     $SECRETCTL_HOME that deletes the *real* vault's item, and it does not
#     self-heal.
#
# Usage, in order:
#
#   ./tests/manual_locked_approval.sh setup    # needs $APPROVAL_WORKER/$APPROVAL_TOKEN
#   ./tests/manual_locked_approval.sh arm      # then lock your screen
#   ./tests/manual_locked_approval.sh check    # after unlocking
#   ./tests/manual_locked_approval.sh cleanup

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"
WORK="${SECRETCTL_MANUAL_WORK:-/tmp/secretctl-locked-approval}"
export SECRETCTL_HOME="$WORK/home"
LOG="$WORK/attempt.log"
PASS="manual-locked-approval-pass"

# The real screen state is the whole point here, so the override must be unset
# rather than pinned. `arm` asserts that below.
unset SECRETCTL_FORCE_LOCKED || true
export SECRETCTL_BATCH=1
export SECRETCTL_AGENT=0            # a warm cache would answer without approval
export SECRETCTL_BATCH_KEYCHAIN=1   # install the keychain protector on init

[[ -x "$BIN" ]] || { echo "binary not found: $BIN — run: zig build" >&2; exit 1; }

sc() { SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }

# Account name of this vault's keychain item = lowercase hex of master_key_id,
# which sits in plaintext at offset 10 of master.key (see master_key.zig).
kc_account() {
  /usr/bin/od -An -v -t x1 -N 16 -j 10 < "$SECRETCTL_HOME/master.key" | tr -d ' \n'
}

case "${1:-}" in
setup)
  if [[ -d "$SECRETCTL_HOME" ]]; then
    echo "already set up at $SECRETCTL_HOME — run cleanup first" >&2
    exit 1
  fi
  # No default URL on purpose: this repo is public, and an approval service's
  # address is deployment-specific, not a constant to bake in.
  : "${APPROVAL_APP_ID:=secretctl}"
  if [[ -z "${APPROVAL_WORKER:-}" || -z "${APPROVAL_TOKEN:-}" ]]; then
    cat >&2 <<'MSG'
Set APPROVAL_WORKER and APPROVAL_TOKEN first:

  APPROVAL_WORKER=https://your-approval-service.example \
  APPROVAL_TOKEN=...                                    \
    ./tests/manual_locked_approval.sh setup

APPROVAL_TOKEN is the service's admin token, which `2fa enroll` presents to
POST /v1/clients (docs/2fa-push-approval.md §9). If yours is stored write-only
— a `wrangler secret`, say — it cannot be read back; use your own copy or
rotate it. APPROVAL_APP_ID defaults to "secretctl".

Both by environment, not argv: `ps` is world-readable.
MSG
    exit 2
  fi

  mkdir -p "$WORK"
  # --touch-id is not the default under SECRETCTL_BATCH_KEYCHAIN: measured, a
  # plain `init` there installs flags=0x00, an ungated protector. That would
  # unlock while locked whether or not this feature works, so the run would
  # "pass" while testing nothing.
  sc init --touch-id >/dev/null
  printf 'sk-locked-approval-canary\n' | sc add CANARY --tag t >/dev/null
  echo "vault created at $SECRETCTL_HOME"
  echo "keychain account (for cleanup): $(kc_account)"

  # Confirm the premise: without a Touch-ID-gated keychain protector there is
  # no gate for approval to stand in for, and the run would prove nothing.
  python3 - "$SECRETCTL_HOME/master.key" <<'PY'
import sys, struct
b = open(sys.argv[1], 'rb').read()
off, n = 34, struct.unpack_from('<I', b, 30)[0]
found = False
for _ in range(n):
    plen  = struct.unpack_from('<I', b, off)[0]
    ptype = struct.unpack_from('<H', b, off + 20)[0]
    blen  = struct.unpack_from('<I', b, off + 30)[0]
    body  = b[off + 34: off + 34 + blen]
    if ptype == 2 and body[:2] == b"S2" and body[2] & 1:
        found = True
    off += 4 + plen
print("ok: keychain protector is Touch ID gated" if found else
      "PREMISE FAILED: no Touch-ID-gated keychain protector — nothing to test")
sys.exit(0 if found else 1)
PY

  echo
  echo "pairing a phone against $APPROVAL_WORKER …"
  SECRETCTL_ENROL_FD=3 "$BIN" 2fa enroll \
    --worker "$APPROVAL_WORKER" --app-id "$APPROVAL_APP_ID" --label "manual-test" \
    3<<<"$APPROVAL_TOKEN"
  echo
  echo "Enter that code in the PWA, then compare fingerprints:"
  echo "  SECRETCTL_HOME=$SECRETCTL_HOME $BIN 2fa status"
  echo
  echo "When the fingerprints match, run: $0 arm"
  ;;

arm)
  [[ -f "$SECRETCTL_HOME/push.json" ]] || { echo "not paired — run setup" >&2; exit 1; }
  if [[ -n "${SECRETCTL_FORCE_LOCKED:-}" ]]; then
    echo "SECRETCTL_FORCE_LOCKED is set — unset it; this run must read the real screen" >&2
    exit 1
  fi
  DELAY="${DELAY:-25}"
  rm -f "$LOG"
  # Detached, so locking the screen cannot take the process down with the
  # terminal session. It records the lock state it observed alongside the
  # result: a run that unlocked because the screen was never locked would
  # otherwise read as a pass.
  nohup bash -c "
    sleep $DELAY
    {
      echo \"=== started \$(date -Iseconds) ===\"
      echo \"screen_is_locked probe: \$(SECRETCTL_HOME='$SECRETCTL_HOME' '$BIN' 2fa status 2>&1 | head -1)\"
      echo '--- list --json ---'
      SECRETCTL_HOME='$SECRETCTL_HOME' SECRETCTL_BATCH=1 SECRETCTL_AGENT=0 \
        '$BIN' list --json 2>&1
      echo \"rc=\$?\"
      echo '--- reveal CANARY ---'
      SECRETCTL_HOME='$SECRETCTL_HOME' SECRETCTL_BATCH=1 SECRETCTL_AGENT=0 \
        '$BIN' reveal CANARY 2>&1
      echo \"rc=\$?\"
    } >> '$LOG' 2>&1
  " >/dev/null 2>&1 &
  echo "armed. LOCK YOUR SCREEN NOW — the attempt starts in ${DELAY}s."
  echo "Approve on the phone when the notification arrives, then unlock and run:"
  echo "  $0 check"
  ;;

check)
  [[ -f "$LOG" ]] || { echo "no attempt recorded yet — did you run arm?" >&2; exit 1; }
  cat "$LOG"
  echo
  echo "PASS looks like: a push arrived while locked, and after approving,"
  echo "list returned CANARY and reveal printed sk-locked-approval-canary."
  echo "FAIL modes worth telling apart:"
  echo "  'screen is locked' + 2fa enroll hint -> pairing was not in effect"
  echo "  'waiting for approval' then Expired  -> push did not arrive or was not tapped"
  echo "  approved, then unlock still failed   -> the gate did not actually open"
  ;;

cleanup)
  if [[ -f "$SECRETCTL_HOME/master.key" ]]; then
    acct="$(kc_account)"
    if security delete-generic-password -s secretctl -a "$acct" >/dev/null 2>&1; then
      echo "deleted keychain item for account $acct"
    else
      echo "no keychain item for account $acct (already gone)"
    fi
  fi
  rm -rf "$WORK"
  echo "removed $WORK"
  echo "note: the paired device stays registered in the approval service; remove it there if you care."
  ;;

*)
  sed -n '2,30p' "$0"
  exit 2
  ;;
esac
