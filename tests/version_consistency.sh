#!/usr/bin/env bash
# The version lives in three files and they must agree. Nothing else checks
# this: the test suites never read flake.nix or the README, and the `nix build`
# job that used to run here compiled the package without comparing anything.
#
# The failure it prevents is quiet — a release where `--version` says one thing
# and the formula says another — and it takes a second instead of the five
# minutes that job cost to cover the same ground worse.
#
# `build.zig.zon`'s `.version` is deliberately excluded: it has read 0.1.0 since
# the beginning and nothing consumes it. See docs/RELEASING.md.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

flake=$(sed -n 's/.*version = "\([0-9][^"]*\)".*/\1/p' flake.nix | head -1)
cli=$(sed -n 's/.*secretctl \([0-9][0-9.]*\)\\n.*/\1/p' src/cli.zig | head -1)
readme=$(sed -n 's/^v\([0-9][0-9.]*\)\. macOS arm64 only.*/\1/p' README.md | head -1)

printf '  flake.nix   %s\n  src/cli.zig %s\n  README.md   %s\n' \
  "${flake:-<not found>}" "${cli:-<not found>}" "${readme:-<not found>}"

fail=0
for pair in "flake.nix:$flake" "src/cli.zig:$cli" "README.md:$readme"; do
  name=${pair%%:*}; val=${pair#*:}
  [[ -n "$val" ]] || { echo "  FAIL no version found in $name"; fail=1; }
done
[[ $fail -eq 0 ]] || { echo; echo "VERSION CHECK FAILED"; exit 1; }

if [[ "$flake" == "$cli" && "$cli" == "$readme" ]]; then
  echo; echo "ALL THREE AGREE: $flake"
else
  echo; echo "VERSION CHECK FAILED: the three do not agree"
  exit 1
fi
