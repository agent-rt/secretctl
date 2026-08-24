#!/usr/bin/env bash
# e2e: the master passphrase must never be readable as a secret value.
#
# Batch mode used to take the passphrase as the first line of stdin and the
# secret value as the second. But whether that first line is consumed depends
# on unlock state: a keychain protector or a warm agent cache satisfies the
# unlock with no passphrase at all, and then the value slot reads the
# *passphrase* line. The passphrase was stored as the secret and written out in
# plaintext by render/materialize.
#
# Both triggers are covered here because each defeated a previous attempt to
# hold the line count stable: SECRETCTL_BATCH_KEYCHAIN was introduced to keep
# the keychain from consuming the unlock, and then the v0.6.0 agent cache
# reintroduced the same shift.
#
# The invariant under test: the stored value is correct for every combination
# of unlock state. It holds because the passphrase has a dedicated channel
# ($SECRETCTL_PASSPHRASE_FD) and fd 0 carries only secret data.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN — run: zig build" >&2
  exit 1
fi

PASS="hunter2hunter2"
VALUE="sk-real-secret-value"
FAILED=0

# One vault per case; the keychain item is keyed by master_key_id so cases
# cannot collide.
run_case() {
  local agent="$1" keychain="$2"
  local work home
  work="$(mktemp -d -t secretctl-batch-ch-XXXXXX)"
  home="$work/home"

  local -a envs=(SECRETCTL_BATCH=1 SECRETCTL_PASSPHRASE_FD=3
                 SECRETCTL_HOME="$home" SECRETCTL_AGENT="$agent")
  [[ "$keychain" == "on" ]] && envs+=(SECRETCTL_BATCH_KEYCHAIN=1)

  env "${envs[@]}" "$BIN" init 3<<<"$PASS" >/dev/null 2>&1
  printf '%s\n' "$VALUE" | env "${envs[@]}" "$BIN" add TOK --tag t 3<<<"$PASS" >/dev/null 2>&1

  # reveal prints "NAME = value"
  local got
  got="$(env "${envs[@]}" "$BIN" reveal TOK 3<<<"$PASS" 2>/dev/null | sed 's/^TOK = //')"

  if [[ "$got" == "$VALUE" ]]; then
    echo "ok: agent=$agent keychain=$keychain stores the value, not the passphrase"
  else
    echo "FAIL: agent=$agent keychain=$keychain stored '$got' (expected '$VALUE')"
    [[ "$got" == "$PASS" ]] && echo "      ^ that is the MASTER PASSPHRASE stored as a secret"
    FAILED=1
  fi

  # Delete exactly the item this case created, addressed by its own
  # master_key_id (master.key header offset 10, 16 bytes).
  #
  # NOT `prune-keychain --yes`: "stale" there means "not the vault at
  # $SECRETCTL_HOME", so running it with a test home deletes the *developer's
  # real* keychain item. Nor bare `security delete-generic-password -s
  # secretctl`, which deletes the first match for the service, whichever vault
  # owns it.
  if [[ -f "$home/master.key" ]]; then
    local acct
    acct="$(/usr/bin/od -An -tx1 -N16 -j10 < "$home/master.key" | tr -d ' \n')"
    if [[ -n "$acct" ]]; then
      # Absent for keychain=off cases, so a non-zero exit here is expected.
      security delete-generic-password -s secretctl -a "$acct" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$work"
  return 0
}

run_case 0 off
run_case 1 off
run_case 0 on
run_case 1 on

# An old-style invocation (passphrase piped on stdin, no channel configured)
# must fail loudly. Silently consuming a line of secret data is the bug.
WORK="$(mktemp -d -t secretctl-batch-ch-legacy-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
set +e
OUT="$(echo "$PASS" | env SECRETCTL_BATCH=1 SECRETCTL_AGENT=0 SECRETCTL_HOME="$WORK/home" \
        "$BIN" init 2>&1)"
EC=$?
set -e
LEGACY_OK=1
[[ $EC -ne 0 ]] || { echo "FAIL: legacy stdin-passphrase init succeeded; it must refuse"; LEGACY_OK=0; }
grep -q "SECRETCTL_PASSPHRASE_FD" <<<"$OUT" \
  || { echo "FAIL: refusal does not name SECRETCTL_PASSPHRASE_FD: $OUT"; LEGACY_OK=0; }
[[ -f "$WORK/home/master.key" ]] && { echo "FAIL: refused init still created a vault"; LEGACY_OK=0; }
if [[ $LEGACY_OK -eq 1 ]]; then
  echo "ok: legacy stdin-passphrase invocation refuses with an actionable message"
else
  FAILED=1
fi

if [[ $FAILED -ne 0 ]]; then
  echo
  echo "BATCH CHANNEL TESTS FAILED"
  exit 1
fi

echo
echo "ALL BATCH CHANNEL TESTS PASSED"
