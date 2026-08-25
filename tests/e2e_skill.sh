#!/usr/bin/env bash
# The skill file tells an agent what it may and may not do. Every factual claim
# in it has to be true, or it is confident misinformation aimed at something
# that will act on it.
#
# An earlier draft claimed `reveal` "refuses anything that is not an interactive
# terminal". Measured: under $SECRETCTL_BATCH it prints the plaintext. That is
# the class of error this suite exists to catch.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/secretctl"
[[ -x "$BIN" ]] || { echo "binary not found: $BIN — run: zig build" >&2; exit 1; }

WORK="$(mktemp -d -t secretctl-skill-e2e-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export SECRETCTL_HOME="$WORK/home" SECRETCTL_BATCH=1 SECRETCTL_AGENT=0 SECRETCTL_FORCE_LOCKED=0
PASS="hunter2hunter2"
FAILED=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; [[ -n "${2:-}" ]] && echo "         $2"; FAILED=1; }
sc()  { SECRETCTL_PASSPHRASE_FD=3 "$BIN" "$@" 3<<<"$PASS"; }

SKILL="$("$BIN" skill)"

# --- shape ---
[[ "$SKILL" == ---* ]] && ok "starts with YAML frontmatter" || bad "no frontmatter"
grep -q '^name: secretctl$' <<<"$SKILL" && ok "declares a name" || bad "no name field"
grep -q '^description: >-' <<<"$SKILL" && ok "declares a description" || bad "no description field"
[[ $("$BIN" skill | wc -l) -gt 40 ]] && ok "has a body" || bad "body is suspiciously short"
"$BIN" skill extra >/dev/null 2>&1 && bad "accepts stray arguments" || ok "rejects stray arguments"

# --- the claims, checked against the binary ---
sc init >/dev/null
printf 'sk-allowed\n'   | sc add my-api-key --tag ai    >/dev/null
printf 'sk-forbidden\n' | sc add OTHER_KEY  --tag other >/dev/null
mkdir -p "$WORK/p"
printf '[allow]\ntags=["ai"]\ncommands=["env"]\n' > "$WORK/p/.secretctl.toml"

# "Names normalise to UPPER_SNAKE_CASE ... my-api-key arrives as $MY_API_KEY"
if (cd "$WORK/p" && sc exec --tag ai -- env 2>/dev/null) | grep -q '^MY_API_KEY='; then
  ok "claim: names normalise to UPPER_SNAKE_CASE"
else
  bad "claim false: my-api-key did not arrive as \$MY_API_KEY"
fi

# "it gates exec only, not reveal" — both halves.
out=$( (cd "$WORK/p" && sc exec --tag other -- env 2>&1) || true)
grep -q "not-allowed-tag" <<<"$out" \
  && ok "claim: the allowlist gates exec" \
  || bad "claim false: exec ignored the allowlist" "${out:0:100}"

out=$( (cd "$WORK/p" && sc reveal OTHER_KEY 2>&1) || true)
grep -q 'sk-forbidden' <<<"$out" \
  && ok "claim: reveal is NOT gated by the allowlist (as the skill says)" \
  || bad "claim stale: reveal now refuses — the skill must be updated" "${out:0:100}"

# "2 you called it wrong ... 1 everything else"
set +e; "$BIN" nosuchcmd >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 2 ]] && ok "claim: exit 2 for an unknown command" \
                || bad "claim false: unknown command exited $rc, not 2"
set +e; sc reveal NOPE >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 2 ]] && ok "claim: exit 2 when a secret name does not exist" \
                || bad "claim false: missing name exited $rc, not 2"
# The other half of the claim: 1 is for a refusal, not a bad request.
set +e; out=$(SECRETCTL_FORCE_LOCKED=1 "$BIN" list --json 2>&1); rc=$?; set -e
[[ $rc -eq 1 ]] && ok "claim: exit 1 when refused at the authorization gate" \
                || bad "claim false: gate refusal exited $rc, not 1" "${out:0:80}"

# Every command the skill names must exist.
while read -r cmd; do
  [[ -z "$cmd" ]] && continue
  set +e; out=$("$BIN" "$cmd" --nonsense-probe 2>&1); set -e
  grep -qi "unknown command" <<<"$out" \
    && bad "skill names a command that does not exist: $cmd" \
    || ok "command exists: $cmd"
done < <(grep -o '^secretctl [a-z0-9-]*' <<<"$SKILL" | awk '{print $2}' | sort -u)

# The skill tells an agent to branch on the name, not the number. So every
# failure must actually print one, in the promised shape.
for probe in "nosuchcmd" "reveal" "reveal NOPE"; do
  set +e; out=$(sc $probe 2>&1 >/dev/null | head -1); set -e
  [[ "$out" == secretctl:\ * ]] \
    && ok "named failure for '$probe': ${out#secretctl: }" \
    || bad "'$probe' failed without a named code" "${out:0:80}"
done

[[ $FAILED -eq 0 ]] || { echo; echo "SKILL E2E FAILED"; exit 1; }
echo; echo "ALL SKILL E2E TESTS PASSED"
