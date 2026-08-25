#!/usr/bin/env bash
# NOT in CI, deliberately.
#
# This checks one thing: that an unreadable TOTP seed does not get overwritten
# by `2fa enroll`. That guard matters — without it a transient keychain problem
# destroys a live enrolment — but the check needs real keychain items, and on a
# GitHub runner that hung the `test` job twice, badly enough to need manual
# cancellation both times. A test that can stall CI for 40 minutes costs more
# than it protects, so it lives here and gets run by hand when the TOTP code
# changes.
#
# Run: bash tests/local_totp_guard.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"
[[ -x "$BIN" ]] || { echo "binary not found: $BIN — run: zig build" >&2; exit 1; }

WORK="$(mktemp -d -t secretctl-totp-guard-XXXXXX)"
export SECRETCTL_HOME="$WORK/home"
export SECRETCTL_BATCH=1 SECRETCTL_AGENT=0 SECRETCTL_FORCE_LOCKED=0
PASS="guard-throwaway"
FAILED=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; [[ -n "${2:-}" ]] && echo "         $2"; FAILED=1; }
sc()  { SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }

cleanup() {
  if [[ -f "$SECRETCTL_HOME/master.key" ]]; then
    a=$(/usr/bin/od -An -v -t x1 -N 16 -j 10 < "$SECRETCTL_HOME/master.key" | tr -d ' \n')
    # By account name. Never `prune-keychain`: with a non-default home it
    # deletes the real vault's item, and that does not self-heal.
    security delete-generic-password -s secretctl -a "$a" >/dev/null 2>&1 || true
    security delete-generic-password -s secretctl -a "$a-totp" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

sc init >/dev/null
sc 2fa enroll >/dev/null
ACCT=$(/usr/bin/od -An -v -t x1 -N 16 -j 10 < "$SECRETCTL_HOME/master.key" | tr -d ' \n')
mdat() { security find-generic-password -s secretctl -a "$ACCT-totp" 2>/dev/null | sed -n 's/.*"mdat".*=\(.*\)/\1/p'; }

# A too-short value stands in for a seed that is present but unusable. Cheaper
# and more deterministic than breaking an ACL, and it exercises the same branch.
security add-generic-password -s secretctl -a "$ACCT-totp" -w "short" -A -U >/dev/null 2>&1

out=$(sc 2fa status 2>&1 || true)
grep -qi "not readable" <<<"$out" \
  && ok "status reports unreadable, not 'not enrolled'" \
  || bad "status misreported an unreadable seed" "${out:0:120}"

BEFORE=$(mdat)
set +e; out=$(sc 2fa enroll 2>&1); rc=$?; set -e
AFTER=$(mdat)
if [[ $rc -ne 0 ]] && [[ -n "$BEFORE" ]] && [[ "$BEFORE" == "$AFTER" ]]; then
  ok "enroll refuses and does not write the item"
else
  bad "enroll wrote the item — this destroys a live enrolment" "rc=$rc before=[$BEFORE] after=[$AFTER]"
fi
grep -qi "do NOT run" <<<"$out" \
  && ok "the message says what not to do" \
  || bad "message does not warn against enrolling" "${out:0:120}"

[[ $FAILED -eq 0 ]] || { echo; echo "TOTP GUARD FAILED"; exit 1; }
echo; echo "TOTP GUARD PASSED"
