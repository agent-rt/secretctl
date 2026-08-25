#!/usr/bin/env bash
# `prune-keychain --yes` must refuse from a non-default $SECRETCTL_HOME.
#
# Its notion of "stale" is "not belonging to the vault at $SECRETCTL_HOME", so
# from a secondary home that also describes the *real* vault's live keychain
# item — and deleting that does not self-heal. This happened during this
# project's own testing; the mitigation until now was a note telling people not
# to run the command.
#
# No keychain writes here: every assertion is about the refusal, which happens
# before enumeration. That keeps it CI-safe, unlike the guard in
# tests/local_totp_guard.sh which needs real items and hung the runner twice.
#
# ############################################################################
# DO NOT FALSIFY THIS SUITE BY DISABLING THE GUARD AND RUNNING IT.
#
# The usual way to prove a guard is load-bearing — break it, watch the test go
# red — destroys real data here. With the guard off, the `--yes` case below is
# permitted, and from this non-default home "stale" means every keychain item
# belonging to any *other* vault. On a developer's machine that is the real
# vault's wrap key and TOTP seed. I did exactly this while writing the suite and
# deleted both; the 2FA enrolment had to be redone from the phone up.
#
# If the guard's behaviour needs re-checking, reason about the condition in
# `cli.zig` or exercise `paths.isDefaultHome` directly. There is no version of
# "just try it and see" that is safe for this one.
# ############################################################################

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"
[[ -x "$BIN" ]] || { echo "binary not found: $BIN — run: zig build" >&2; exit 1; }

WORK="$(mktemp -d -t secretctl-prune-e2e-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export SECRETCTL_BATCH=1 SECRETCTL_AGENT=0 SECRETCTL_FORCE_LOCKED=0
PASS="hunter2hunter2"
FAILED=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; [[ -n "${2:-}" ]] && echo "         $2"; FAILED=1; }

# A vault in a throwaway home. `init` writes a keychain item only when
# SECRETCTL_BATCH_KEYCHAIN is set, which it deliberately is not.
SECRETCTL_HOME="$WORK/home" SECRETCTL_PASSPHRASE_FD=3 "$BIN" init 3<<<"$PASS" >/dev/null

set +e
out=$(SECRETCTL_HOME="$WORK/home" "$BIN" prune-keychain --yes 2>&1); rc=$?
set -e
[[ $rc -ne 0 ]] && ok "non-default home: --yes is refused (rc=$rc)" \
                || bad "non-default home: --yes was allowed" "${out:0:120}"
grep -q "unsafe-prune" <<<"$out" \
  && ok "non-default home: refusal carries the named code" \
  || bad "refusal is not named" "${out:0:120}"
grep -q "unset \$SECRETCTL_HOME" <<<"$out" \
  && ok "non-default home: the message says how to proceed safely" \
  || bad "refusal gives no way forward" "${out:0:160}"

# The dry run must still work — seeing the real vault's account listed as
# "would delete" is the clearest explanation of the hazard there is.
set +e
out=$(SECRETCTL_HOME="$WORK/home" "$BIN" prune-keychain 2>&1); rc=$?
set -e
grep -q "not the default vault" <<<"$out" \
  && ok "non-default home: the dry run warns" \
  || bad "dry run gave no warning" "${out:0:120}"

# Explicitly naming the default path is still the default vault. Refusing it
# would be a lie about what is dangerous.
set +e
out=$(SECRETCTL_HOME="$HOME/.secretctl" "$BIN" prune-keychain 2>&1); rc=$?
set -e
grep -q "not the default vault" <<<"$out" \
  && bad "explicit default path was treated as non-default" "${out:0:120}" \
  || ok "explicit \$HOME/.secretctl counts as the default vault"

[[ $FAILED -eq 0 ]] || { echo; echo "PRUNE GUARD E2E FAILED"; exit 1; }
echo; echo "ALL PRUNE GUARD E2E TESTS PASSED"
