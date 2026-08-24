#!/usr/bin/env bash
# Cross-language seal check: Zig seals, the PWA's own code opens.
#
# The interop vectors in src/p256_test.zig only cover JS-seals -> Zig-opens.
# The direction that actually failed in production was the other one, and no
# amount of Zig-side testing could have caught it: a self-consistent
# implementation of a subtly different construction passes every round-trip
# test and then fails on a phone.
#
# Skips when the nudge checkout is absent, since it needs the PWA source.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="${NUDGE_PWA_CORE:-$HOME/ai-workspace/agent-rt/nudge/pwa/nudge-core.js}"

if [[ ! -f "$CORE" ]]; then
  echo "nudge PWA source not found at $CORE — skipping cross-language seal check" >&2
  exit 0
fi
command -v node >/dev/null || { echo "node not installed — skipping" >&2; exit 0; }

WORK="$(mktemp -d -t sc-xlang-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/probe.zig" <<'ZIG'
const std = @import("std");
const p256 = @import("p256.zig");
pub fn main(init: std.process.Init) u8 {
    const a = init.gpa;
    const argv = init.minimal.args.toSlice(init.arena.allocator()) catch return 1;
    if (argv.len < 5) return 2;
    const sealed = p256.sealB64(a, argv[1], argv[2], argv[3], argv[4]) catch |e| {
        std.debug.print("SEALFAIL {s}\n", .{@errorName(e)});
        return 1;
    };
    defer a.free(sealed);
    const b64 = p256.b64uEncodeAlloc(a, sealed) catch return 1;
    defer a.free(b64);
    std.debug.print("{s}\n", .{b64});
    return 0;
}
ZIG
cp "$ROOT/src/p256.zig" "$ROOT/src/rand.zig" "$WORK/"
( cd "$WORK" && zig build-exe probe.zig -femit-bin=probe -lc >/dev/null 2>&1 ) \
  || { echo "FAIL: could not build the seal probe"; exit 1; }

NUDGE_CORE="$CORE" ZIG_PROBE="$WORK/probe" node --input-type=module -e '
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
const b64u = u => Buffer.from(u).toString("base64")
  .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");

let fails = 0;
const check = (name, cond, detail) => {
  if (cond) console.log("  ok   " + name);
  else { console.log("  FAIL " + name); if (detail) console.log("         " + detail); fails++; }
};

globalThis.self = globalThis;
new Function(await readFile(process.env.NUDGE_CORE, "utf8")).call(globalThis);

const kp = await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
const pub = b64u(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));

const seal = (reqId, appId, pt) => execFileSync("/bin/sh", ["-c",
  `"$ZIG_PROBE" "${pub}" "${reqId}" "${appId}" ${JSON.stringify(pt)} 2>&1`],
  { encoding: "utf8" }).trim();

const reqId = b64u(crypto.getRandomValues(new Uint8Array(16)));
const appId = "app-xlang";
const pt = JSON.stringify({ title: "secretctl · unlock vault",
  details: [["command","list --json"],["secrets","A, B"]],
  grace_options_s: [0,300,900], require_device_unlock: true });

const sealed = seal(reqId, appId, pt);
check("zig produced an envelope", /^[A-Za-z0-9_-]+$/.test(sealed), sealed.slice(0,60));

try {
  const out = await globalThis.Nudge.unsealWith(kp.privateKey, sealed, reqId, appId);
  check("the PWA opens what zig sealed", JSON.stringify(out) === pt);
} catch (e) {
  check("the PWA opens what zig sealed", false, e.message || String(e));
}

// The AAD and the salt must both be load-bearing in this direction too.
for (const [name, rid, aid] of [
  ["wrong app_id refused", reqId, "app-other"],
  ["wrong req_id refused", b64u(crypto.getRandomValues(new Uint8Array(16))), appId],
]) {
  let opened = false;
  try { await globalThis.Nudge.unsealWith(kp.privateKey, sealed, rid, aid); opened = true; } catch {}
  check(name, !opened);
}

process.exit(fails ? 1 : 0);
'
echo
echo "ALL CROSS-LANGUAGE SEAL TESTS PASSED"
