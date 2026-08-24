# Two-factor unlock and out-of-band approval

Status: **design, not implemented.** Written 2026-08-24.

Motivating problem: with the screen locked (or the operator simply away from
the machine), `secretctl` is close to unusable. An agent asks for a secret,
the unlock path demands Touch ID, and there is no finger on the sensor.

This document records what was measured, why the obvious framing of the
problem is wrong, and the design that follows from the measurements. It is
scoped to the unlock path; it does not change the vault body format or the
`exec` capability model.

Relationship to TECH-DESIGN: this adds one protector type (§3.x) and one
agent opcode family. Nothing here alters §2.2 (master.key layout) or §4.1
(vault layout).

**How to read this after the fact.** Parts have been overtaken by
`2fa-push-approval.md`, which specifies what was actually built. What has not
been overtaken, and is the reason to keep this document: the measurements in
§1, the security model in §2 — cited by that document to justify calling itself
a consent gate rather than a factor — and §4.2, the 2-of-2 protector, which is
still the only design for real cryptographic 2FA here and is unbuilt. Each
superseded section says so at its head.

---

## 1. Evidence

Claims below are tagged by how they were established. This matters: the
design turns on the difference between "the keychain enforces it" and "an
`if` statement enforces it", and only measurement separates those.

### 1.1 Measured on this machine, 2026-08-24

| # | Claim | Method |
|---|---|---|
| M1 | The login keychain is `no-timeout` — it does **not** lock on screen lock or on idle. | `security show-keychain-info ~/Library/Keychains/login.keychain-db` |
| M2 | This vault has exactly two protectors: `passphrase` (type 1) and `macos_keychain` (type 2), the latter with body flags `0x01` (`Flags.touch_id`). | `xxd` over `~/.secretctl/master.key`, decoded against the §2.2 layout |
| M3 | The keychain wrap key reads out with **interaction explicitly forbidden**: `SecItemCopyMatching` with `kSecUseAuthenticationUIFail` returns `errSecSuccess` and 32 bytes. | Purpose-built ObjC probe against the real item (`service=secretctl`, `account=hex(mk_id)`) |
| M4 | The agent cache is active with a 300 s sliding TTL. | `SECRETCTL_AGENT=1`, `SECRETCTL_AGENT_TTL=300` in the environment |

**M3 is the load-bearing measurement.** The Touch ID requirement is not
enforced by the keychain item's access control. It is enforced by
`keychain.zig:313`:

```zig
if (body_flags == @intFromEnum(Flags.touch_id)) {
    const ok = local_auth.evaluate("Unlock secretctl vault");
    if (!ok) return Error.AuthenticationFailed;
}
```

Any process running as this user can skip that branch entirely and read the
wrap key directly. The gate is a consent prompt, not a cryptographic barrier.

### 1.2 Read from the source (certain, not measured)

- **Protectors are a disjunction.** `master_key.zig:186-222` walks the
  protector list and stops at the first one that unwraps (`if (unlocked)
  continue`). Any single protector suffices.
- **The biometric policy has no password fallback.** `local_auth.m` uses
  `LAPolicyDeviceOwnerAuthenticationWithBiometrics`, not
  `LAPolicyDeviceOwnerAuthentication`.
- **The biometric wait is unbounded.** `local_auth.m:49` waits
  `DISPATCH_TIME_FOREVER` on the reply semaphore.
- **The MCP passphrase fallback is unreachable.** `mcp_tools.zig:96` claims
  the prompt is "read from /dev/tty via tty module so we don't read from
  JSON-RPC stdin", but `tty.zig` uses `STDIN: c_int = 0` throughout
  (lines 11, 124, 142) and never opens `/dev/tty`. Under an MCP server stdin
  is the JSON-RPC pipe, so `isStdinTty()` is false and `readSecret` returns
  `ReadError.NoTty` before prompting.
- **`SECRETCTL_BATCH` would corrupt the MCP stream.** `readSecret`'s batch
  branch (`tty.zig:120`) runs *before* the tty check and reads a line from
  fd 0 — under MCP that consumes a JSON-RPC frame as the password.
- **The cache TTL is capped at 3600 s.** `agent.zig:87`.

### 1.3 Not yet measured — the one open question

What `LAContext` does while the screen is locked:

- does `canEvaluatePolicy(...WithBiometrics)` return YES or NO?
- does `evaluatePolicy` invoke its reply block, or never fire?

This decides whether the observed symptom is *hang forever* (reply never
comes, combined with `DISPATCH_TIME_FOREVER`) or *immediate failure*
(`canEvaluatePolicy` returns NO, so `evaluate` returns 0 and the code falls
through to a passphrase prompt that has no TTY). Both are broken, but they
are broken differently and want different fixes — see §5.

The probe for this is written and needs an operator to lock the screen while
it runs. Until it is run, §5 items 1 and 2 are provisional.

---

## 2. What the current security model actually is

From M2, M3 and the disjunction in §1.2:

```
mk  =  passphrase   OR   (ability to execute code as this uid on this Mac)
```

That is **1-of-2, not 2FA.** And the second disjunct is exactly what an agent
running on this machine already has. The only thing standing between a
compromised or merely careless agent and the master key is the `if` in
`keychain.zig:313`, which is not a security boundary against code running as
the user.

The consequence for this design: **a second factor is only worth adding if it
is cryptographically load-bearing.** Another consent `if` — a TOTP check, a
confirmation prompt — adds friction to the honest path without moving the
adversary's cost. This rules out a whole family of otherwise appealing cheap
options; see §4.1.

---

## 3. Requirements

- **R1 — Remote satisfiable.** With the operator away from the machine, an
  agent's request must be *approvable*, not merely *refusable*.
- **R2 — Genuine 2FA.** Neither the Mac alone (keychain + disk + code
  execution as the user) nor the operator's knowledge alone should yield the
  master key.
- **R3 — No silent hangs.** The unattended path must fail fast and legibly, or
  block with a bounded, explicit timeout. Never `DISPATCH_TIME_FOREVER`.
- **R4 — Capability model preserved.** `exec` still injects without exposing
  plaintext; this work governs *authorization*, not the injection path.
- **R5 — Recoverable.** Adding a second required factor must not create a
  single point of permanent vault loss.

---

## 4. Design

**What in here is still the plan.** §4.2 (the 2-of-2 protector) is the only
route to a genuine second cryptographic factor and is unimplemented; push
approval does not replace it, because a consent gate leaves the key reachable
by one factor. §4.4 and §4.5 are live. §4.1, §4.3 and §4.6 are superseded as
mechanisms by `2fa-push-approval.md` and carry notes saying so — §4.1's
*reasoning* still stands and is why that design looks the way it does.

### 4.1 The structural move: approval is out-of-band from the requester

> **Superseded as a mechanism, not as a reason.** The insight below — that
> approval must not be prompted for by the requesting process — is what the
> whole push design rests on. The specific mechanism, promoting `agent.zig`
> into a local broker with a `secretctl approve` CLI, is not being built: the
> out-of-band channel is now the phone (`2fa-push-approval.md`), and the Mac
> side is one blocking HTTPS GET rather than a local rendezvous. Read this
> section for why, not for what to implement.

The reason R1 is hard has nothing to do with cryptography. When the operator
is remote, the process that needs the key is an **agent process on the Mac**,
and it does not have the operator's terminal. SSHing in from a phone does not
help: the passphrase prompt lives in the agent's process, not in the new
shell. Any design where the requester prompts for the second factor fails R1
by construction.

So the approval channel must be separate from the requesting process. The
right home already exists: `src/agent.zig`. It is a per-uid unix-socket
daemon that holds master keys in RAM keyed by `master_key_id`, with
`getpeereid()` checks and `secureZero` on eviction. Promote it from *cache*
to *cache + approval broker*:

```
requester (CLI / MCP)  ──unix socket──>  agent daemon (cache + broker)
                                               ▲
                                               │ approvals
                         ┌─────────────────────┼─────────────────────┐
                     ssh + passphrase      TOTP code          phone push
                       (§4.3, v1)          (§4.1 note)         (§4.6)
```

Flow on a cache miss:

1. Requester asks the daemon for `mk`. Miss.
2. Daemon registers a **pending request** — `request_id`, requesting command,
   secret name if applicable, pid, timestamp — and returns
   `approval_required(request_id)` **instead of blocking on Touch ID**.
3. The requester either (a) returns a clean "approval required, run
   `secretctl approve <id>`" error, or (b) blocks with an explicit bounded
   timeout, per §4.5.
4. The operator, from anywhere, runs `secretctl approve <id>`. That command
   has its *own* TTY, prompts for the second factor there, reconstructs `mk`,
   and hands it to the daemon.
5. The daemon caches `mk` under the normal TTL and releases the waiter.

**The notification channel needs no infrastructure in v1.** The operator is
already in a conversation with the agent; the agent surfaces
`secretctl approve <id>` in chat. Push notification (§4.6) is a UX upgrade,
not a prerequisite.

> Note on TOTP. A TOTP front-end fits this broker cleanly and is convenient
> (six digits beats a long passphrase over a phone keyboard). But it must be
> understood as an *approval channel*, not a factor: the seed would live in
> the same keychain as the wrap key, so anyone who can read the keychain can
> mint codes. Per §2 it does not move the adversary's cost. Ship it, if at
> all, as ergonomics on top of a real second factor — never as the second
> factor.

### 4.2 Protector type 5 — two-of-two

New `ProtectorType.keychain_and_passphrase = 5` (values 1–3 are taken;
`protector.zig:22`). Splitting the key, rather than nesting the wraps, is
deliberate: the second share's *provenance* becomes a swappable detail, so
§4.6 changes who holds a share without touching this format.

```
S_mac    32 random bytes, stored in the keychain
         (service "secretctl", account hex(mk_id) — as today, cf. M3)
S_2nd    32 random bytes, AEAD-wrapped under argon2id(passphrase, salt)
         and stored in this protector's body

K   = HKDF-SHA256(salt = protector_id,
                  ikm  = S_mac || S_2nd,
                  info = "secretctl 2of2 v1")
mk  = AES-GCM-open(K, nonce, aad = mk_id || protector_id, ct, tag)
```

Using an AEAD over the combined shares rather than a bare
`mk = S_mac XOR S_2nd` is a deliberate ergonomics choice: the GCM tag
authenticates *both* shares, so a wrong passphrase produces a clean
`AuthenticationFailed` that the retry loop can report as "incorrect
password". With bare XOR the error surfaces downstream as a file-HMAC
mismatch (`master_key.zig:235`), which reads to the operator as vault
corruption.

Body layout, following the §3.1 common header:

```
  "S3"                     2   magic (distinct from "S2" keychain bodies)
  flags                    1   bit0: also require the Touch ID gate on S_mac
  kc_service_len           2   u16 LE
  kc_service               n
  kc_account_len           2   u16 LE
  kc_account               n   hex(mk_id), 32 bytes today
  argon2_m_kib             4   u32 LE   \
  argon2_t                 4   u32 LE    | params persisted per-protector,
  argon2_p                 4   u32 LE    | as passphrase protectors already do
  argon2_version           4   u32 LE   /
  salt_len                 2   u16 LE
  salt                     n   16 bytes
  s2nd_nonce              12
  s2nd_ct_len              2   u16 LE
  s2nd_ct                 32   AEAD-wrapped S_2nd
  s2nd_tag                16
  mk_nonce                12
  mk_ct_len                2   u16 LE
  mk_ct                   32
  mk_tag                  16
```

Argon2id defaults come from `argon2.zig`: m = 65536 KiB, t = 3, p = 1,
version 0x13. Both AEAD operations bind `aad = mk_id || protector_id`, as
`keychain.zig:buildAad` already does, so a protector body cannot be
transplanted between vaults or between protector slots.

`parseAndUnlock` gains one `switch` case. Note that this protector needs the
passphrase on the *first* pass, whereas today's first pass deliberately
passes `password = null` to try keychain-only. The unlock driver therefore
needs restructuring: probe which protector types are present before deciding
whether to prompt, rather than prompting only after a keychain miss.

### 4.3 Second factor in v1: the passphrase

> **Not the chosen v1.** Push approval is (`2fa-push-approval.md`). This
> section stays because it remains the cheapest *cryptographic* second factor
> and the natural companion to §4.2 — push approval is a consent gate and does
> not make the key 2-of-2, so if that is ever wanted, this is still the design.

The passphrase is already implemented, already remote-typeable over SSH, and
requires no new hardware, service, or phone app. Combined with §4.1 it
satisfies R1 and R2 together:

- R2: the Mac alone yields only `S_mac`. Useless without `S_2nd`.
- R1: `secretctl approve <id>` runs in the operator's own SSH session, where
  a passphrase prompt works.

Cost is one passphrase entry per cache window, which the existing agent TTL
already amortizes.

### 4.4 Recovery (R5) — not optional

Two-of-two means losing either share loses the vault. Ship these *with* the
feature, not after:

- **`secretctl key export-recovery`** — emit a one-time 32-byte recovery
  share (base32, or BIP39 words for transcription) that is installed as its
  own standalone protector. Destination: password manager or paper. This is
  deliberately a 1-of-N escape hatch; its whole purpose is to survive the
  loss of a 2-of-2 half.
- **Explicit downgrade** — `secretctl key set-policy 1of2|2of2`, so an
  operator who finds the tradeoff wrong can walk it back with the vault in
  hand rather than by editing bytes.

### 4.5 Behaviour per call site

| Call site | On cache miss |
|---|---|
| Interactive CLI with a TTY | Prompt in place, as today. No broker round-trip needed. |
| `exec` under an agent | Register request, block with a bounded timeout (default 120 s, `--approval-timeout`), then fail with the request id. |
| MCP `get_secret` / `run_with_secrets` | Register request, return `approval_required` **immediately** with the id and the exact command to run. Never block a JSON-RPC handler. |
| Non-interactive, no broker running | Fail fast with the reason. Never prompt into a pipe. |

Every registered request and every approval or denial goes to the JSONL audit
log via `audit.zig`, including which factor satisfied it.

### 4.6 Later: phone-held share

The §4.2 format already accommodates this — replace "`S_2nd` wrapped under
argon2id(passphrase)" with "`S_2nd` wrapped to an X25519 public key whose
private half lives in the phone's Secure Enclave". The broker gains a second
approval front-end; nothing else changes. Transport options, cheapest first:

- **ntfy or MQTT relay.** Mac publishes the request; phone subscribes, shows
  it, posts back `S_2nd` sealed to a per-request ephemeral X25519 key so the
  relay never sees plaintext. Adds a network dependency to the unlock path.
- **Native iOS app.** Face ID on the phone gates release of the share. Best
  UX, and the only option where the second factor is hardware-bound. Note the
  constraint from the deploy model: the Mac binary is ad-hoc signed, so a
  Developer ID would be a prerequisite for a real distributed app.

Deferred deliberately: it is a service plus phone-side work, and §4.1 + §4.3
already remove the urgency.

**Superseded in part.** The chosen direction is not the phone-held *share*
described above but a lock-conditional **consent gate**: Touch ID while
someone is at the machine, phone approval over a Cloudflare Workers relay when
the screen is locked. Specified in **[`2fa-push-approval.md`](2fa-push-approval.md)**.

Note what that trades away. A gate that only applies when locked cannot be a
cryptographic factor, because Touch-ID-at-the-desk remains an unconditional
path to the key and M3 shows the Mac can take that path without any
interaction. So the push flow defends against *absence* — an agent wanting
keys while nobody is there — not against code execution as this uid. The
2-of-2 protector in §4.2 is still the thing that would make it a real factor,
and it remains unimplemented.

---

## 5. Bugs to fix alongside

These are independent of which factor is chosen, and are part of why the
locked-screen case is as bad as it is.

1. **Unbounded biometric wait** (`local_auth.m:49`). Replace
   `DISPATCH_TIME_FOREVER` with a bounded `dispatch_semaphore_wait` and
   return a third state (`timed_out`) distinct from "declined", so the caller
   can pick a different path instead of inheriting a hang. *Provisional on
   §1.3: if the reply block does fire promptly while locked, the timeout is
   defence-in-depth rather than the fix.*
2. **No password fallback in the LA policy** (`local_auth.m`). Consider
   `LAPolicyDeviceOwnerAuthentication`, which admits the Mac login password.
   Marginal for this use case — it helps over Screen Sharing, not over SSH —
   but it is a one-symbol change. *Also provisional on §1.3.*
3. ~~**Unreachable MCP passphrase fallback**~~ — **fixed.** The fallback is
   removed rather than repaired: there is no correct terminal for an MCP
   server to prompt on. fd 0 is the transport, and the controlling terminal
   belongs to whoever spawned the server, so a prompt there is invisible to
   the operator driving the agent and reading it steals the parent's input.
   The unlock is now keychain-only and returns `error.VaultLocked`, which
   `errorResult` renders as instructions the agent can relay. Out-of-band
   approval (§4.1) is the real answer.
4. ~~**`SECRETCTL_BATCH` corrupts the MCP stream**~~ — **fixed**, at the
   choke point rather than per-call-site: `tty.reserveStdin()` marks fd 0 as a
   protocol transport, and both functions that read fd 0 (`readLine`,
   `readSecret`) refuse with `ReadError.StdinReserved`. The check precedes the
   `batchMode()` branch, which is the specific ordering bug. `mcp.serve()`
   calls it once at startup.

   This was **worse than "unreachable"**. Measured A/B against brew v0.6.2 with
   a passphrase-only vault and `SECRETCTL_BATCH=1` (the same env `e2e_mcp.sh`
   sets): three request frames in, only ids 1 and 2 answered — frame 3 was
   consumed as the master password, and id 2 came back
   `AuthenticationFailed` because a JSON line was tried as a passphrase. After
   the fix: ids 1, 2, 3 all answered. Regression test:
   `tests/e2e_mcp_locked.sh`, which fails on v0.6.2 at exactly that
   assertion. `e2e_mcp.sh` could never catch it — it always sets
   `SECRETCTL_BATCH_KEYCHAIN=1`, so the keychain unlock always succeeds and
   the fallback is never entered.
5. ~~**Batch-mode stdin is positional but the number of lines consumed is
   not**~~ — **fixed.** In batch mode stdin was a positional script
   (`password\nvalue\n`), but whether the password line is read depends on
   whether the unlock actually prompts — and a warm agent cache skips it. Then
   line 1 shifts into the *value* slot. Measured on identical inputs:

   ```
   SECRETCTL_AGENT=0 -> GITHUB_TOKEN renders as: ghp_test-token-67890
   SECRETCTL_AGENT=1 -> GITHUB_TOKEN renders as: hunter2hunter2   # the passphrase
   ```

   So the master password is stored as a secret value and then written in
   plaintext into whatever `render`/`materialize` produces. This is why
   `tests/e2e.sh` failed at "render missing GITHUB_TOKEN value" on any machine
   where `SECRETCTL_AGENT=1` is exported — reproduced identically on brew
   v0.6.2, so it was not a regression.

   The agent cache was **not** the only trigger. With the agent fully off and
   `SECRETCTL_BATCH_KEYCHAIN=1`, a keychain protector absorbs the unlock and
   produces the same shift — measured: `TOK = hunter2hunter2`. So
   `tests/e2e_mcp.sh`, which sets that variable, had been storing the master
   passphrase as every secret value while still reporting a pass; it never
   asserted on a value.

   That is the argument against fixing this by disabling whatever might
   consume the unlock. `SECRETCTL_BATCH_KEYCHAIN` was itself introduced to
   hold the line count stable (see the comment it replaced in `cli.zig`), and
   the v0.6.0 agent cache promptly broke it again. Two logical inputs on one
   unframed channel cannot be made deterministic that way, so the fix gives
   them separate channels: the passphrase comes from
   `$SECRETCTL_PASSPHRASE_FD` and fd 0 carries only secret data. When a
   passphrase is needed with no channel and no terminal, the command now
   **refuses with an actionable message** rather than silently consuming a
   line. Regression test: `tests/e2e_batch_channel.sh` asserts the stored
   value is correct across all four agent × keychain combinations.
6. **`prune-keychain --yes` deletes other vaults' items with no confirmation**
   (`cli.zig` prune path). *Found the hard way while testing; not yet fixed.*
   "Stale" is computed relative to whichever vault `$SECRETCTL_HOME` points
   at, so running it with a test or secondary home deletes the **real** vault's
   keychain item. There is no dry-run diff of *which* vault each item belongs
   to, and no confirmation beyond `--yes`.

   Damage is recoverable but not self-healing: `master.key` still lists the
   `macos_keychain` protector, and the missing item surfaces as
   `KeychainItemNotFound` (`keychain.zig:178`), which the v0.6.1 self-heal does
   not cover — that only triggers on `InteractionRequired`. So the unlock
   silently degrades to passphrase-only until `secretctl reinstall-keychain`
   is run. Suggested fixes: refuse when `$SECRETCTL_HOME` is not the default
   unless `--force`, and name the owning vault per item in the dry-run output.
   Tests must not use it for cleanup — delete the specific account instead
   (`tests/e2e_batch_channel.sh` shows the pattern). Note `manual_touch_id.sh`
   still runs `security delete-generic-password -s secretctl`, which deletes
   the first match for the service regardless of owner: same hazard.

Also worth revisiting once §4.1 lands: the 3600 s TTL cap (`agent.zig:87`)
exists to bound exposure of a cached key, which is the right instinct while
Touch ID is the only unlock path. With an out-of-band approval channel the
tradeoff shifts — an explicit, audited `secretctl unlock --for 8h` before
leaving is more honest than an operator ratcheting the TTL env var upward.

---

## 6. Interim mitigation, no code

`SECRETCTL_AGENT_TTL=3600` (the cap) plus one deliberate unlock before
walking away buys a one-hour window. It does not address R1 or R2 — it only
widens the gap between prompts.

---

## 7. Multi-machine consequence

The vault syncs across Macs over git. A 2-of-2 protector on *this* Mac while
another Mac still carries a single-factor keychain protector means the
effective security level is set by the weakest machine — an adversary with
the vault file just uses the other machine's protector. Either upgrade every
machine in the same change, or record the decision to accept 1-of-N on the
others. Note also the caveat already standing in `cli.zig:359`:
`healKeychainProtector` drops *all* keychain protectors and adds one for the
current machine, which is wrong once per-Mac protectors coexist.

---

## 8. Open questions

1. §1.3 — the locked-screen `LAContext` measurement. Blocks §5 items 1 and 2.
2. Should `S_mac` keep the Touch ID gate (`flags` bit 0) when a real second
   factor exists? Doing so means a locked screen blocks even an approved
   request, which defeats the purpose. The default should probably be *off*
   for type-5 protectors, with the gate available for operators who want
   presence *and* knowledge while at the desk.
3. Does the broker approve *a request* or *a window*? Per-request approval is
   tighter and gives a real audit trail; per-window matches the existing TTL
   cache and is far less annoying. Likely both, with per-request as the
   default for `get_secret` and per-window for `exec`.
4. Where do pending requests live? In-daemon memory is simplest and dies with
   the daemon; a file under `~/.secretctl/` survives a restart but adds a
   surface that must not leak the requesting context.
