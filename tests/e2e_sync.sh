#!/usr/bin/env bash
# e2e for cross-Mac sync via git: add-keychain-protector + sync.
# All paths run with SECRETCTL_BATCH=1 so we don't hit Touch ID prompts.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN — run: zig build" >&2
  exit 1
fi

WORK="$(mktemp -d -t secretctl-sync-e2e-XXXXXX)"
A="$WORK/host-a"
B="$WORK/host-b"
BARE="$WORK/origin.git"
mkdir -p "$A" "$B"
export SECRETCTL_BATCH=1

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

PASS="hunter2hunter2"

# ---------- bootstrap host A ----------
SECRETCTL_HOME="$A" "$BIN" init <<<"$PASS" >/dev/null
echo "ok: init A"

# Initial protector count = 1 (only passphrase since SECRETCTL_BATCH_KEYCHAIN unset)
COUNT=$(/usr/bin/od -An -t u4 -N 4 -j 30 < "$A/master.key" | tr -d ' ')
[[ "$COUNT" == "1" ]] || { echo "FAIL: expected 1 protector, got $COUNT"; exit 1; }
echo "ok: A starts with 1 protector"

# Add a keychain protector for host A
SECRETCTL_HOME="$A" "$BIN" key add-keychain-protector --no-touch-id <<<"$PASS" >/dev/null
COUNT=$(/usr/bin/od -An -t u4 -N 4 -j 30 < "$A/master.key" | tr -d ' ')
[[ "$COUNT" == "2" ]] || { echo "FAIL: after first add expected 2, got $COUNT"; exit 1; }
echo "ok: A has 2 protectors after add-keychain-protector"

# Add a secret on A so we can verify the vault round-trips through git
printf "%s\nsecret-from-A\n" "$PASS" | SECRETCTL_HOME="$A" "$BIN" add SHARED_TOKEN --tag t >/dev/null
echo "ok: A added SHARED_TOKEN"

# ---------- git push from A ----------
cd "$A"
git init -q -b main
git add -A
git -c user.email=a@example -c user.name=a commit -q -m "init from A"
git --bare init -q "$BARE"
git remote add origin "$BARE"
git push -q -u origin main
echo "ok: A pushed to bare origin"

# ---------- clone on host B ----------
cd "$WORK"
rm -rf "$B"
git clone -q "$BARE" "$B"
chmod 700 "$B"
chmod 600 "$B/master.key" "$B/vault" "$B/config.toml"

# B can read A's vault immediately because passphrase protector still works.
LIST_B=$(SECRETCTL_HOME="$B" "$BIN" list --json <<<"$PASS")
echo "$LIST_B" | grep -q '"name":"SHARED_TOKEN"' || { echo "FAIL: B can't see SHARED_TOKEN"; exit 1; }
echo "ok: B sees SHARED_TOKEN via cloned vault"

# B adds its own keychain protector
SECRETCTL_HOME="$B" "$BIN" key add-keychain-protector --no-touch-id <<<"$PASS" >/dev/null
COUNT=$(/usr/bin/od -An -t u4 -N 4 -j 30 < "$B/master.key" | tr -d ' ')
[[ "$COUNT" == "3" ]] || { echo "FAIL: B expected 3 protectors, got $COUNT"; exit 1; }
echo "ok: B has 3 protectors after add-keychain-protector"

# Configure git on B for sync test
cd "$B"
git config user.email b@example
git config user.name b

# ---------- sync no-git scenario ----------
ROOT_NOGIT="$WORK/nogit"
mkdir -p "$ROOT_NOGIT"
SECRETCTL_HOME="$ROOT_NOGIT" "$BIN" init <<<"$PASS" >/dev/null
set +e
NOGIT_OUT="$(SECRETCTL_HOME="$ROOT_NOGIT" "$BIN" sync 2>&1)"
NOGIT_EC=$?
set -e
[[ $NOGIT_EC -eq 2 ]] || { echo "FAIL: sync without git expected exit 2, got $NOGIT_EC"; exit 1; }
echo "$NOGIT_OUT" | grep -q "not a git repository" || { echo "FAIL: sync output missing 'not a git repository'"; exit 1; }
echo "ok: sync exits 2 when not a git repo"

# ---------- sync push from B ----------
SECRETCTL_HOME="$B" "$BIN" sync >/dev/null
echo "ok: B sync pushed (B's new protector now in origin)"

# ---------- sync pulls B's new protector down to A ----------
cd "$A"
SECRETCTL_HOME="$A" "$BIN" sync >/dev/null
COUNT=$(/usr/bin/od -An -t u4 -N 4 -j 30 < "$A/master.key" | tr -d ' ')
[[ "$COUNT" == "3" ]] || { echo "FAIL: A after sync should see 3 protectors, got $COUNT"; exit 1; }
echo "ok: A sync pulled B's new protector"

# ---------- diverged history ----------
# A modifies, B modifies, both commit, A pushes, B sync should fail diverged.
printf "%s\nfrom-a-2\n" "$PASS" | SECRETCTL_HOME="$A" "$BIN" add A_ONLY --tag t >/dev/null
SECRETCTL_HOME="$A" "$BIN" sync >/dev/null
echo "ok: A pushed A_ONLY"

printf "%s\nfrom-b-2\n" "$PASS" | SECRETCTL_HOME="$B" "$BIN" add B_ONLY --tag t >/dev/null
# B already committed locally via add → has local commit. A's push made remote ahead.
# B's sync flow: add -A (no-op since add already changed vault — but vault is committed?
# Let me re-check: secretctl add modifies the vault file, doesn't commit. So B has uncommitted change.
# sync will: add -A → commit → pull --ff-only → diverged → bail
set +e
SECRETCTL_HOME="$B" "$BIN" sync 2>/dev/null
EC=$?
set -e
[[ $EC -eq 1 ]] || { echo "FAIL: B sync after divergence should exit 1, got $EC"; exit 1; }
echo "ok: B sync detects diverged history and bails (exit 1)"

# ---------- audit log ----------
LOG=~/Library/Logs/secretctl.log
[[ -f "$LOG" ]] || { echo "FAIL: no audit log"; exit 1; }
tail -30 "$LOG" | grep -q '"op":"key.add-keychain-protector"' || { echo "FAIL: key.add-keychain-protector not in audit"; exit 1; }
tail -30 "$LOG" | grep -q '"op":"sync"' || { echo "FAIL: sync not in audit"; exit 1; }
echo "ok: audit log has key.add-keychain-protector and sync events"

echo
echo "ALL SYNC E2E TESTS PASSED"
