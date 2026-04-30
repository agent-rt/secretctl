#!/usr/bin/env bash
# End-to-end smoke test for secretctl Phase 1.
# Runs against a freshly-built binary in a sandboxed $SECRETCTL_HOME.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN" >&2
  echo "run: zig build" >&2
  exit 1
fi

WORK="$(mktemp -d -t secretctl-e2e-XXXXXX)"
export SECRETCTL_HOME="$WORK/home"
PROJECT="$WORK/project"
mkdir -p "$PROJECT"

cleanup() {
  rm -rf "$WORK"
  # Best-effort: clear any keychain item this test may have created.
  # (Not strictly required because account is master_key_id-based and unique.)
}
trap cleanup EXIT

export SECRETCTL_BATCH=1
PASS="hunter2hunter2"

# ---------- init ----------
printf "%s\n" "$PASS" | "$BIN" init >/dev/null

[[ -f "$SECRETCTL_HOME/master.key" ]] || { echo "FAIL: master.key not created"; exit 1; }
[[ -f "$SECRETCTL_HOME/vault" ]]      || { echo "FAIL: vault not created"; exit 1; }
[[ "$(/usr/bin/stat -f %A "$SECRETCTL_HOME/master.key")" == "600" ]] || { echo "FAIL: master.key not 0600"; exit 1; }
[[ "$(/usr/bin/stat -f %A "$SECRETCTL_HOME/vault")"      == "600" ]] || { echo "FAIL: vault not 0600"; exit 1; }
echo "ok: init"

# ---------- add ----------
printf "%s\nsk-test-token-12345\n" "$PASS" | "$BIN" add NPM_TOKEN --tag npm,ci >/dev/null
printf "%s\nghp_test-token-67890\n" "$PASS" | "$BIN" add GITHUB_TOKEN --tag github >/dev/null
echo "ok: add"

# ---------- list ----------
LIST_JSON="$(printf "%s\n" "$PASS" | "$BIN" list --json)"
echo "$LIST_JSON" | grep -q '"name":"NPM_TOKEN"'   || { echo "FAIL: list --json missing NPM_TOKEN"; exit 1; }
echo "$LIST_JSON" | grep -q '"name":"GITHUB_TOKEN"' || { echo "FAIL: list --json missing GITHUB_TOKEN"; exit 1; }
echo "$LIST_JSON" | grep -q "sk-test-token"        && { echo "FAIL: list --json leaked secret value"; exit 1; }
echo "ok: list --json (no value leak)"

# Tag filter.
LIST_NPM="$(printf "%s\n" "$PASS" | "$BIN" list --json --tag npm)"
echo "$LIST_NPM" | grep -q '"name":"NPM_TOKEN"' || { echo "FAIL: --tag npm missing NPM_TOKEN"; exit 1; }
echo "$LIST_NPM" | grep -q '"name":"GITHUB_TOKEN"' && { echo "FAIL: --tag npm should exclude GITHUB_TOKEN"; exit 1; }
echo "ok: list --tag filter"

# ---------- exec without policy: should still work since policy is permissive when absent ----------
cd "$PROJECT"
ENV_OUT="$(printf "%s\n" "$PASS" | "$BIN" exec --tag npm -- env | grep '^NPM_TOKEN=' || true)"
[[ "$ENV_OUT" == "NPM_TOKEN=sk-test-token-12345" ]] || { echo "FAIL: exec did not inject NPM_TOKEN; got '$ENV_OUT'"; exit 1; }
echo "ok: exec --tag injects env"

# ---------- exec exit code passthrough ----------
set +e
printf "%s\n" "$PASS" | "$BIN" exec --tag npm -- sh -c 'exit 7'
EC=$?
set -e
[[ $EC -eq 7 ]] || { echo "FAIL: exit code passthrough; got $EC"; exit 1; }
echo "ok: exec exit code passthrough"

# Nonexistent command → 127.
set +e
printf "%s\n" "$PASS" | "$BIN" exec --tag npm -- /this/does/not/exist
EC=$?
set -e
[[ $EC -eq 127 ]] || { echo "FAIL: not-found exit; got $EC"; exit 1; }
echo "ok: exec ENOENT → 127"

# ---------- exec with restrictive policy ----------
cat > "$PROJECT/.secretctl.toml" <<EOF
[allow]
tags = ["npm"]
commands = ["env"]
EOF

# allowed
printf "%s\n" "$PASS" | "$BIN" exec --tag npm -- env >/dev/null
echo "ok: policy allows env+npm"

# disallowed command
set +e
printf "%s\n" "$PASS" | "$BIN" exec --tag npm -- sh -c 'echo bad'
EC=$?
set -e
[[ $EC -eq 2 ]] || { echo "FAIL: policy should reject sh; got $EC"; exit 1; }
echo "ok: policy rejects disallowed command"

# disallowed tag
set +e
printf "%s\n" "$PASS" | "$BIN" exec --tag github -- env
EC=$?
set -e
[[ $EC -eq 2 ]] || { echo "FAIL: policy should reject github tag; got $EC"; exit 1; }
echo "ok: policy rejects disallowed tag"

rm "$PROJECT/.secretctl.toml"

# ---------- exec with no selection rejects ----------
set +e
printf "%s\n" "$PASS" | "$BIN" exec -- env
EC=$?
set -e
[[ $EC -eq 2 ]] || { echo "FAIL: exec without --tag/--only should exit 2; got $EC"; exit 1; }
echo "ok: exec requires explicit selection"

# ---------- render ----------
cat > "$PROJECT/npmrc.tmpl" <<'EOF'
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
EOF
printf "%s\n" "$PASS" | "$BIN" render "$PROJECT/npmrc.tmpl" --out "$PROJECT/.npmrc" >/dev/null
grep -q "sk-test-token-12345" "$PROJECT/.npmrc"   || { echo "FAIL: render missing NPM_TOKEN value"; exit 1; }
grep -q "ghp_test-token-67890" "$PROJECT/.npmrc"  || { echo "FAIL: render missing GITHUB_TOKEN value"; exit 1; }
[[ "$(/usr/bin/stat -f %A "$PROJECT/.npmrc")" == "600" ]] || { echo "FAIL: rendered file not 0600"; exit 1; }
echo "ok: render → .npmrc with 0600"

# ---------- vault file leaks no metadata ----------
if strings "$SECRETCTL_HOME/vault" 2>/dev/null | grep -qE 'NPM_TOKEN|GITHUB_TOKEN|sk-test-token'; then
  echo "FAIL: vault file leaks plaintext name or value"
  exit 1
fi
echo "ok: vault is opaque to strings(1)"

# ---------- rm ----------
printf "%s\n" "$PASS" | "$BIN" rm GITHUB_TOKEN >/dev/null
LIST_AFTER="$(printf "%s\n" "$PASS" | "$BIN" list --json)"
echo "$LIST_AFTER" | grep -q '"name":"GITHUB_TOKEN"' && { echo "FAIL: rm did not remove"; exit 1; }
echo "ok: rm"

# ---------- editor: add --editor ----------
WRITE_NEW="$WORK/write-new-editor.sh"
cat > "$WRITE_NEW" <<'EOF'
#!/bin/sh
printf "multi-line\nsecret-via-editor\n" > "$1"
EOF
chmod +x "$WRITE_NEW"

EDITOR="$WRITE_NEW" printf "%s\n" "$PASS" | env EDITOR="$WRITE_NEW" "$BIN" add MULTILINE --tag editor --editor >/dev/null
REVEAL="$(printf "%s\n" "$PASS" | "$BIN" reveal MULTILINE)"
case "$REVEAL" in
  *"multi-line"*)
    case "$REVEAL" in
      *"secret-via-editor"*) ;;
      *) echo "FAIL: editor add second line missing"; exit 1 ;;
    esac
    ;;
  *) echo "FAIL: editor add did not create multi-line value"; exit 1 ;;
esac
echo "ok: add --editor (multi-line via fake editor)"

# ---------- editor: edit unchanged (cat) ----------
NOOP="$WORK/noop-editor.sh"
cat > "$NOOP" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$NOOP"
EDIT_OUT="$(printf "%s\n" "$PASS" | env EDITOR="$NOOP" "$BIN" edit MULTILINE)"
echo "$EDIT_OUT" | grep -q "unchanged" || { echo "FAIL: noop editor should report unchanged"; exit 1; }
REVEAL2="$(printf "%s\n" "$PASS" | "$BIN" reveal MULTILINE)"
[[ "$REVEAL" == "$REVEAL2" ]] || { echo "FAIL: noop editor altered value"; exit 1; }
echo "ok: edit (no-op editor) leaves value unchanged"

# ---------- editor: edit replaces value ----------
REPLACE="$WORK/replace-editor.sh"
cat > "$REPLACE" <<'EOF'
#!/bin/sh
printf "%s" "completely-new-secret" > "$1"
EOF
chmod +x "$REPLACE"
printf "%s\n" "$PASS" | env EDITOR="$REPLACE" "$BIN" edit MULTILINE >/dev/null
REVEAL3="$(printf "%s\n" "$PASS" | "$BIN" reveal MULTILINE)"
case "$REVEAL3" in
  *"completely-new-secret"*) ;;
  *) echo "FAIL: editor edit did not replace value (got: $REVEAL3)"; exit 1 ;;
esac
echo "ok: edit (modifying editor) replaces value"

# ---------- editor: tags preserved across edit ----------
TAGS_AFTER_EDIT="$(printf "%s\n" "$PASS" | "$BIN" list --json | grep -o '"name":"MULTILINE"[^}]*')"
case "$TAGS_AFTER_EDIT" in
  *"editor"*) ;;
  *) echo "FAIL: edit should preserve tags (got: $TAGS_AFTER_EDIT)"; exit 1 ;;
esac
echo "ok: edit preserves tags"

# ---------- editor: empty content cancels add --editor ----------
EMPTY="$WORK/empty-editor.sh"
cat > "$EMPTY" <<'EOF'
#!/bin/sh
: > "$1"
EOF
chmod +x "$EMPTY"
set +e
printf "%s\n" "$PASS" | env EDITOR="$EMPTY" "$BIN" add EMPTY_SECRET --editor 2>/dev/null
EC=$?
set -e
[[ $EC -eq 1 ]] || { echo "FAIL: empty editor add should exit 1, got $EC"; exit 1; }
LIST_FINAL="$(printf "%s\n" "$PASS" | "$BIN" list --json)"
echo "$LIST_FINAL" | grep -q '"name":"EMPTY_SECRET"' && { echo "FAIL: empty editor must not create secret"; exit 1; }
echo "ok: add --editor with empty content exits 1 and creates nothing"

# ---------- materialize: simple token ----------
TOKEN_OUT="$WORK/token-out"
printf "%s\n" "$PASS" | "$BIN" materialize NPM_TOKEN --out "$TOKEN_OUT" >/dev/null
[[ "$(/usr/bin/stat -f %A "$TOKEN_OUT")" == "600" ]] || { echo "FAIL: materialize default mode not 0600"; exit 1; }
[[ "$(cat "$TOKEN_OUT")" == "sk-test-token-12345" ]] || { echo "FAIL: materialize content mismatch"; exit 1; }
# Verify no trailing newline (file size == value size)
[[ "$(wc -c < "$TOKEN_OUT" | tr -d ' ')" == "$(printf "sk-test-token-12345" | wc -c | tr -d ' ')" ]] || { echo "FAIL: materialize added newline"; exit 1; }
echo "ok: materialize single-line, 0600, no trailing newline"

# ---------- materialize: --mode override ----------
printf "%s\n" "$PASS" | "$BIN" materialize NPM_TOKEN --out "$TOKEN_OUT.0644" --mode 0644 >/dev/null
[[ "$(/usr/bin/stat -f %A "$TOKEN_OUT.0644")" == "644" ]] || { echo "FAIL: materialize --mode 0644"; exit 1; }
echo "ok: materialize --mode override"

# ---------- materialize: --mkdir creates parent ----------
NESTED="$WORK/nested/deep/dir/secret"
printf "%s\n" "$PASS" | "$BIN" materialize NPM_TOKEN --out "$NESTED" --mkdir >/dev/null
[[ -f "$NESTED" ]] || { echo "FAIL: --mkdir didn't create nested"; exit 1; }
[[ "$(/usr/bin/stat -f %A "$WORK/nested/deep/dir")" == "700" ]] || { echo "FAIL: parent dir not 0700"; exit 1; }
echo "ok: materialize --mkdir creates parents"

# ---------- materialize: missing secret → exit 2 ----------
set +e
printf "%s\n" "$PASS" | "$BIN" materialize NOT_A_SECRET --out "$WORK/x" 2>/dev/null
EC=$?
set -e
[[ $EC -eq 2 ]] || { echo "FAIL: missing secret should exit 2, got $EC"; exit 1; }
echo "ok: materialize missing secret exits 2"

# ---------- editor: temp files left behind? ----------
LEFTOVER=$(ls "$WORK"/secretctl-edit-* 2>/dev/null || true)
if [[ -n "$LEFTOVER" ]]; then
  # The temp files are in $TMPDIR, not WORK; check the real dir.
  :
fi
LEFTOVER_REAL=$(ls /tmp/secretctl-edit-* 2>/dev/null || ls "${TMPDIR:-/tmp}"/secretctl-edit-* 2>/dev/null || true)
[[ -z "$LEFTOVER_REAL" ]] || { echo "FAIL: leftover editor tempfile: $LEFTOVER_REAL"; exit 1; }
echo "ok: no editor tempfiles left behind"

# ---------- audit log written ----------
LOG="$HOME/Library/Logs/secretctl.log"
[[ -f "$LOG" ]] && grep -q 'op=' "$LOG" 2>/dev/null && true   # informational; not asserted

echo
echo "ALL E2E TESTS PASSED"
