# Push approval: Touch ID at the desk, phone 2FA when locked

Status: **proposed design, awaiting confirmation. No code written yet.**
Written 2026-08-24. Concrete realisation of `2fa-design.md` §4.6.

Requirement, as stated: on `secretctl list` (and every other command that
unlocks the vault), detect whether the screen is locked. If it is, require
authorization out of band, via a Cloudflare Workers relay, a PWA, and Web
Push on iOS and Android. Both authorization methods are supported: **Touch ID
when someone is at the machine, push 2FA when the screen is locked.**

---

## 1. What this is, and what it is not

It is a **consent gate**: it forces a human tap before an agent gets secrets
while nobody is at the machine. That is the threat that motivated the whole
exercise, and this addresses it directly.

It is **not** a second cryptographic factor. From `2fa-design.md` M3: the
keychain wrap key comes out of the keychain with interaction explicitly
forbidden (`kSecUseAuthenticationUIFail` → `errSecSuccess`, 32 bytes). So while
the screen is locked the Mac can still derive the master key entirely on its
own, and "require approval when locked" is an `if` that any code running as
this uid can skip. A lock-conditional gate cannot be cryptographic while an
unconditional path to the key exists — and Touch-ID-at-the-desk *is* such a
path, by design here.

Two honest consequences to keep in view:

- **On a compromised host, the approval prompt's text is only as trustworthy
  as the binary that produced it.** The Mac composes the "what am I
  approving" description; malicious local code can describe one thing and do
  another. The gate still stops silent exfiltration — something has to make
  your phone buzz and wait for a tap — but do not read the description as
  proof.
- **Defence is against absence, not against compromise.** It answers "an
  agent wanted a key while I was away and I did not consent." It does not
  answer "an attacker has code execution on my Mac."

Upgrade path to a real factor, unchanged from `2fa-design.md` §4.2/§4.6: move
the wrap key into the data-protection keychain behind a biometry-gated
`SecAccessControl`, and/or give the phone a real key share. Both need a
Developer ID signature (this binary is ad-hoc signed — see the deploy model),
so both are out of scope here. The protocol below is arranged so that adding a
phone-held share later changes the payload, not the transport.

---

## 2. Authorization methods

| Screen state | Method | Rationale |
|---|---|---|
| unlocked | Touch ID (existing `LAContext` gate) | a finger is available; no round trip, no network |
| locked | push approval | no finger available |
| unknown (ssh-only login, launchd, no console) | push approval | no finger available either; fail closed |

### 2.1 Lock detection

Confirmed against a genuinely locked screen, not only through the override:
with the Mac locked, `CGSSessionScreenIsLocked=1` and every unlocking command
refused at the gate. That was discovered by accident — the whole test suite went
red at once — which is itself the finding recorded in §2.3.

`CGSessionCopyCurrentDictionary()`, called from the CLI. Measured on
macOS 25.5 with an ad-hoc signed binary: works with no entitlement, no TCC
prompt, no window-server connection of our own.

The key detail — **while unlocked, `CGSSessionScreenIsLocked` is absent, not
present-and-false**:

```
kCGSSessionOnConsoleKey          = 1
kCGSessionLoginDoneKey           = 1
kCGSSessionUserNameKey           = <user>
...
verdict: CGSSessionScreenIsLocked=<absent>  onConsole=1
```

So the predicate is "key present and true ⇒ locked". Additionally
`kCGSSessionOnConsoleKey == 0` (fast-user-switched away) counts as locked, and
both keys absent means no GUI session at all ⇒ `unknown` ⇒ fail closed.

`SECRETCTL_FORCE_LOCKED=1|0` overrides the query, so the locked path is
testable without locking the screen. Any non-empty value other than `0` means
locked — the override fails closed too.

### 2.4 A stale service worker is indistinguishable from a bug

The first real locked-screen approval failed with the phone reporting a key
mismatch, and every server-side fact checked out: right app, right device,
right sealed length, push accepted, and the pinned keys matching the
service's byte for byte. A cross-language test then showed the sealing
construction itself was fine in the failing direction.

The cause was that the phone's service worker predated the fix. The page
rendered correct values using new code while an *old* worker did the
decrypting, and the old worker read `app_id` from a legacy single-registration
record — the JS client's app, not the asking client's. Wrong AAD, so no key
could have worked.

Two things came out of it, both applied:

- **Never name a culprit in a decryption error.** The message said the sealing
  key did not match, which sent the investigation at keys. The seal key, the
  `req_id` and the `app_id` all feed the same AEAD; the message now says so and
  reports the values actually used.
- **Make the running build visible.** The worker answers a build query and the
  page shows both its own stamp and the worker's. A worker older than the page
  means the behaviour being observed is not the code being read. `bun run
  deploy` stamps before deploying.

The general form, which is the third variant of it in this project: when
behaviour contradicts freshly written code, establish *which build is running*
before doubting the code.

### 2.2b Measured: a Touch-ID-gated keychain protector is unusable while locked

This settles §1.3 of `2fa-design.md` and changes what §4.2 there is *for*.

Two vaults, real locked screen, no passphrase fd supplied — so only the keychain
path could succeed and no passphrase fallback could mask the result:

| keychain protector | approval | unlock |
|---|---|---|
| `flags=0x00`, no Touch ID gate | approved, signature verified | **succeeded**, secret returned |
| `flags=0x01`, Touch ID gate | approved, signature verified | **failed** after 13 s |

The 13 s matters: the biometric gate **fails fast** while locked, it does not
hang. So the unbounded `DISPATCH_TIME_FOREVER` in `local_auth.m` is not the
cause of the original symptom — `canEvaluatePolicy`/`evaluatePolicy` simply
refuses. That downgrades §5 item 1 from "the likely bug" to defence in depth,
and it means the original "screen locked and everything hangs" report was the
*passphrase prompt with no TTY*, not the biometric prompt.

**The consequence is not a nicety.** A consent gate and a Touch ID gate are
mutually exclusive while the screen is locked, because the thing that proves a
human consented cannot also satisfy a check that requires a finger on a sensor
that is unavailable. Three configurations resolve it:

1. **A keychain protector without the Touch ID gate.** Works today, as measured.
   The cost is giving up the at-the-desk biometric prompt, and M3 already shows
   that gate is an application-level `if` rather than a barrier — anything
   running as this uid can read the wrap key regardless.
2. **The 2-of-2 protector of `2fa-design.md` §4.2**, specified in
   `2of2-protector.md`. The phone releases a key share as part of approving, so
   approval *produces* the key instead of authorising a step that then cannot be
   satisfied.
3. **Keep the gate; let a verified approval stand in for it.** ← shipped, §2.2c.

### 2.2c Shipped: approval stands in for the gate

`keychain.Gate` is threaded into `keychain.unwrap` from the single place that
knows an approval verified. `.approved_out_of_band` skips the biometric prompt;
every other caller keeps `.require_biometric`, so the at-the-desk prompt is
untouched and the two contexts stop competing for the same protector.

This is the right first step rather than a shortcut past option 2, and the
reason is worth stating because it is easy to get backwards. The gate is an
in-process `if` before `SecItemCopyMatching`, not an ACL on the item (M3: a
data-protection item with `kSecAccessControlBiometryAny` needs a Developer ID
signature). Anything running as this uid reads the wrap key without going near
LocalAuthentication. So:

- Removing an *unsatisfiable* gate widens nothing. The attacker with code
  execution never had to satisfy it.
- **Option 2 buys nothing on its own either.** A 2of2 protector added alongside
  the existing ones leaves the vault a disjunction — `master_key.zig:157` takes
  the first protector that unwraps — so the phone stays bypassable until the
  migration in `2of2-protector.md` §4 *removes* the standalone protectors. That
  migration is a separate decision with a real cost: it is what takes away
  one-touch unlock at the desk.

So option 3 is honestly an **operational** fix, not a security upgrade: the
locked screen goes from "approval succeeds, unlock fails anyway" to "works",
and the threat model is exactly what it was before. Anyone reading this looking
for the security upgrade wants §4 of `2of2-protector.md`.

What this does buy, and what a bypass would have to defeat: the gate opens only
for a verdict whose signature verified against a key pinned at pairing. Present
push.json, unreachable service, denial, timeout, and forged verdict all leave it
closed (`e2e_lockstate.sh`).

The MCP server goes through the same decision, which is the case this work
started from — an agent asking for a secret with nobody at the machine — and the
one where it matters most, since an MCP server has no interactive channel at all
and approval from another device is its only path.

Every earlier note in these documents calling §4.2 "stronger but optional" is
wrong on this point, and is corrected: it is not optional *if the goal is making
the phone a factor*. It was never the prerequisite for making a locked screen
unlockable — that is this section. Both corrections came out of running the
thing, not from reading it.

### 2.3 Every test suite must pin the lock state

Adding the gate made the entire e2e suite fail whenever the developer's screen
happened to be locked, because refusing every unlock is exactly correct
behaviour. A suite whose result depends on whether a human is looking at the
screen is not a test.

So every suite now exports `SECRETCTL_FORCE_LOCKED=0`, and the lockstate suite
sets it explicitly on both sides. This is the third variable in this project to
need pinning for the same reason, after `SECRETCTL_AGENT` (a warm cache masked a
positional-stdin bug) and `VISUAL` (it outranks `EDITOR`, so a developer's real
editor got spawned against a pipe). The pattern is worth naming: anything the
product reads from the environment has to be pinned by the tests, or the
environment silently becomes an input.

### 2.2 Where the check goes

At the **top of the unlock path**, before the agent cache and before the
keychain. This matters: the agent cache holds the master key for
`$SECRETCTL_AGENT_TTL` (default 300 s, up to 3600 s), so if the check came
after the cache, locking the screen would leave a window in which no approval
is required at all. Checking first makes the gate independent of cache state.

Cost: while locked, every unlocking command needs an approval round trip, even
back-to-back ones. §6.4 covers the grace window that makes that tolerable.

---

## 3. Components

```
  ┌──────────────────────────── Mac ────────────────────────────┐
  │  secretctl (CLI / MCP)                                      │
  │    lockstate.m   CGSessionCopyCurrentDictionary             │
  │    local_auth.m  Touch ID          (unlocked path)          │
  │    push_auth.zig request + verify  (locked path)            │
  │    http.m        NSURLSession                               │
  │    ~/.secretctl/push.json  0600                             │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ HTTPS, P-256 signed
                                 ▼
  ┌─────────────────── Cloudflare Worker ───────────────────────┐
  │  relay only — holds no plaintext, cannot approve            │
  │  Durable Object per Mac: enrolled devices, pending requests │
  │  VAPID (RFC 8292) sender · serves the PWA as static assets  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ Web Push
                                 ▼
  ┌──────────────── PWA (installed, iOS / Android) ─────────────┐
  │  service worker: push → fetch detail → decrypt → notify     │
  │  P-256 keypair, non-extractable, IndexedDB                  │
  │  Approve / Deny → signed verdict                            │
  └─────────────────────────────────────────────────────────────┘
```

One Worker deployment serves both the API and the PWA, so there is a single
thing to deploy and no CORS.

### 3.1 The relay is untrusted

Two properties, both enforced on the Mac and neither dependent on Cloudflare
behaving:

- **The Worker cannot approve.** A verdict is signed by the phone's private
  key; the Mac verifies it against a public key it pinned at enrolment. A
  Worker that fabricates an approval produces a signature the Mac rejects.
- **The Worker cannot read what is being approved.** The description — which
  contains secret *names*, exactly the metadata this project encrypts at rest
  — is sealed to the phone's public key before it leaves the Mac. The Worker
  stores an opaque blob. It learns timing, sizes, and that *a* request
  happened.

Cloudflare does see: your Mac's IP, the phone's push endpoint, request
timing and frequency. That is the cost of using a relay at all.

### 3.2 Curve choice

**P-256 everywhere.** ECDSA-P256-SHA256 for signatures, ECDH-P256 →
HKDF-SHA256 → AES-256-GCM for the sealed description.

Why not Ed25519/X25519, which are nicer in Zig: WebCrypto support for them is
recent (Safari 17+), and the phone side has to work on whatever the user's iOS
version is. P-256 ECDSA and ECDH are universally available in WebCrypto and
allow non-extractable keys. Zig covers both sides —
`std.crypto.sign.ecdsa.EcdsaP256Sha256` and `std.crypto.ecc.P256` for the ECDH
scalar multiply.

---

## 4. Enrolment

One-time, per phone.

1. `secretctl 2fa enroll` on the Mac. It generates the Mac's P-256 keypair if
   absent, then registers with the Worker and receives a short-lived
   **pairing code** (8 chars, 10 min TTL, single use).
2. The Mac prints the PWA URL and the code, plus a QR of both.
3. On the phone: open the URL in Safari (iOS) or Chrome (Android) and
   **install it to the Home Screen**. On iOS this is mandatory — Web Push does
   not work for a Safari tab, only for an installed PWA (iOS 16.4+).
4. Open the installed app, enter the pairing code, tap "Enable approvals".
   That user gesture is what lets the browser grant notification permission —
   iOS will not grant it outside one.
5. The PWA generates its non-extractable P-256 keypair, subscribes to push
   with the VAPID public key, and posts `{pairing_code, device_pubkey,
   push_subscription}` to the Worker.
6. The Mac polls until pairing completes, then **pins `device_pubkey`** in
   `~/.secretctl/push.json` and prints a fingerprint. The phone shows the same
   fingerprint; they must match. That check is what stops a Worker from
   substituting its own key at enrolment — the one moment when it otherwise
   could.

`secretctl 2fa status` lists pinned devices with fingerprints and last-seen.
`secretctl 2fa remove <fingerprint>` unpins locally and revokes on the Worker.
`secretctl 2fa test` runs a full approval round trip without touching a secret.

---

## 5. Approval protocol

```
Mac                          Worker                        Phone (PWA)
 │                              │                              │
 │ 1 build request              │                              │
 │   req_id  16B random         │                              │
 │   purpose sealed to dev_pk   │                              │
 │   sign with mac_sk           │                              │
 ├─ POST /v1/request ──────────>│                              │
 │                              │ verify mac sig, store, TTL   │
 │                              ├─ Web Push (no payload) ─────>│
 │                              │                              │ SW wakes
 │                              │<─ GET /v1/pending ───────────┤
 │                              ├─ sealed purpose ────────────>│ decrypt,
 │                              │                              │ notify
 │<─ long-poll /v1/request/:id ─┤                              │
 │        (20 s holds)          │<─ POST /v1/verdict ──────────┤ tap
 │                              │   {req_id, verdict, ts}      │
 │                              │   signed with dev_sk         │
 │<─ signed verdict ────────────┤                              │
 │                              │                              │
 │ 2 verify sig against pinned dev_pk                          │
 │   check req_id matches, ts fresh, not expired               │
 │ 3 approved → proceed with the normal keychain unlock        │
```

### 5.1 Signed request (Mac → Worker)

```
canonical = "secretctl-req-v1" ‖ mac_id ‖ req_id ‖ ts ‖ ttl ‖ sha256(sealed_purpose)
sig       = ECDSA-P256-SHA256(mac_sk, canonical)
```

The Worker verifies `sig` against the Mac's pinned public key before sending
any push. Without that, anyone who learns a `mac_id` could ring the phone at
will.

### 5.2 Sealed purpose (Mac → phone, opaque to the Worker)

```
eph_sk, eph_pk = P-256 keygen                  (fresh per request)
shared         = ECDH(eph_sk, dev_pk)
key            = HKDF-SHA256(salt = req_id, ikm = shared,
                             info = "secretctl-purpose-v1")
sealed_purpose = eph_pk ‖ nonce ‖ AES-256-GCM(key, nonce, aad = req_id ‖ mac_id,
                                              plaintext = purpose_json)
```

`purpose_json` is what the human reads:

```json
{
  "cmd":     "list",
  "args":    "--json",
  "secrets": ["OPENAI_API_KEY", "NPM_TOKEN"],
  "tags":    ["ai"],
  "pid":     41203,
  "cwd":     "/Users/x/proj",
  "host":    "<hostname>",
  "at":      "2026-08-24T11:02:10Z"
}
```

`aad` binds the ciphertext to this request and this Mac, so a sealed purpose
cannot be replayed into a different request.

### 5.3 Signed verdict (phone → Mac, via the Worker)

```
canonical = "secretctl-verdict-v1" ‖ req_id ‖ verdict ‖ ts
sig       = ECDSA-P256-SHA256(dev_sk, canonical)
```

The Mac accepts only if: the signature verifies against a **pinned** device
key; `req_id` equals the request it is waiting on; `ts` is within ±120 s;
the request has not expired; and this `req_id` has not been used before.
`verdict` is `approve` or `deny`. Anything else, including a timeout, is a
denial.

### 5.4 Why the Mac verifies rather than trusting a 200

The Worker's answer is data, not authority. Everything the Mac acts on is
signed by a key the Worker never holds. This is the difference between "a
relay I depend on for delivery" and "a service I have to trust with my
secrets", and it is worth the extra ~60 lines.

---

## 6. Worker

### 6.1 Endpoints

| Method | Path | Caller | Purpose |
|---|---|---|---|
| POST | `/v1/enroll/mac` | Mac | register `mac_id` + pubkey, get pairing code |
| GET | `/v1/enroll/status` | Mac | poll for pairing completion |
| POST | `/v1/enroll/device` | PWA | redeem pairing code, submit device pubkey + push subscription |
| POST | `/v1/request` | Mac | create approval request, trigger push |
| GET | `/v1/request/:id` | Mac | long-poll for the signed verdict |
| GET | `/v1/pending` | PWA | fetch sealed purpose for a woken push |
| POST | `/v1/verdict` | PWA | submit signed verdict |
| POST | `/v1/device/remove` | Mac | revoke a device |
| GET | `/*` | phone | the PWA itself (static assets) |

### 6.2 State

One Durable Object per `mac_id`: pinned Mac pubkey, enrolled devices (push
subscription + device pubkey + last seen), pending requests, used-`req_id`
set. A DO also gives the long-poll somewhere to park.

**Check your Cloudflare plan before committing to this.** Durable Objects
historically needed the Workers Paid plan; SQLite-backed DOs have since
appeared on lower tiers, and I am not going to assert which applies to your
account. If DOs are unavailable, the fallback is KV plus short polling — KV's
eventual consistency and coarse TTLs are a poor fit for a 120 s handshake, so
confirming the plan is the first deploy step, not an afterthought.

### 6.3 Retention

Pending requests are deleted on verdict or expiry, default TTL 120 s. Used
`req_id`s are kept for 24 h for replay rejection. Nothing else persists beyond
the enrolment record. All stored request material is the sealed blob.

### 6.4 Grace window

Approving every command individually while locked is unusable — a single
`exec` may unlock several times. So a verdict carries a `grace` field the
phone sets: **this request only**, or **all requests for N minutes** (5 / 15 /
60). The Mac honours a grace window by caching the approval locally, keyed to
the screen-lock session, and drops it the moment the screen unlocks or
re-locks. Default offered on the notification: this request only, with grace
as a second tap.

`get_secret` over MCP is always per-request, never covered by grace — it is
the one operation that hands plaintext to an agent.

---

## 7. PWA

- Served from the Worker; installed to the Home Screen (mandatory on iOS).
- `manifest.webmanifest`, a service worker, one HTML page. No framework, no
  build step, no external requests — same spirit as the CLI.
- Device keypair: `crypto.subtle.generateKey` with
  `{name:"ECDSA", namedCurve:"P-256"}`, `extractable: false`, stored as a
  `CryptoKey` in IndexedDB. It cannot be exported, by construction.
- Service worker: on `push`, fetch the sealed purpose, decrypt with the ECDH
  key, `showNotification` with actions **Approve** / **Deny** / **Approve
  5 min**. `notificationclick` posts the signed verdict without opening the
  page.
- Every push must result in a visible notification — iOS revokes push
  permission from apps that receive pushes silently.

### 7.1 Push payload: the one thing to verify first

The design sends a **payload-less push** (VAPID-authenticated wake only) and
has the service worker fetch the sealed purpose over HTTPS. That avoids
implementing RFC 8291 `aes128gcm` payload encryption in the Worker entirely,
and the confidentiality it would provide is already covered by our own
sealing.

Chrome/Android delivers payload-less pushes. **I have not verified that Safari
on iOS does** — Apple requires a notification to be shown, which we do, but
whether a data-less push is delivered at all needs a real device test. If it
is not, the fallback is implementing RFC 8291 in the Worker (ECDH P-256 +
HKDF + AES-128-GCM, all available in Workers WebCrypto, ~80 lines) and putting
`{req_id}` in the encrypted payload. Either way the sealed purpose stays E2E.

This is the first thing to test on your actual iPhone, before the rest is
built out.

---

## 8. Mac client

### 8.1 New files

| File | Role |
|---|---|
| `src/lockstate.m` / `.zig` | screen-lock detection (§2.1) — written and validated |
| `src/http.m` / `.zig` | NSURLSession POST/GET with a bounded timeout |
| `src/push_auth.zig` | request build, seal, long-poll, verdict verify |
| `src/p256.zig` | ECDSA verify + ECDH over `std.crypto.ecc.P256` |

HTTP goes through NSURLSession rather than `std.http.Client`: the std HTTP/TLS
surface has churned across Zig releases, and this project already has the ObjC
bridge pattern (`local_auth.m`) with a `dispatch_semaphore` to make an async
API synchronous. It also keeps request bodies out of `argv`, which shelling
out to `curl` would not.

### 8.2 Config — `~/.secretctl/push.json`, 0600

```json
{
  "worker_url": "https://secretctl-approve.<subdomain>.workers.dev",
  "mac_id": "…", "mac_pubkey": "…", "mac_privkey": "…",
  "devices": [{"fingerprint": "…", "pubkey": "…", "label": "iPhone",
               "enrolled_at": "…"}],
  "request_timeout_s": 120,
  "fail_closed": true
}
```

`mac_privkey` authenticates requests to the Worker; it grants no access to the
vault, so it lives in the file rather than the keychain. Nothing in this file
can decrypt a secret.

### 8.3 New commands

```
secretctl 2fa enroll [--worker URL] [--label NAME]
secretctl 2fa status
secretctl 2fa remove FINGERPRINT
secretctl 2fa test
```

### 8.4 Failure modes

| Condition | Behaviour |
|---|---|
| locked, no devices enrolled | refuse, naming `secretctl 2fa enroll` |
| locked, network unreachable | refuse (`fail_closed`) |
| locked, push undelivered / phone off | refuse at timeout (120 s) |
| locked, explicit deny | refuse immediately |
| verdict signature invalid | refuse, log loudly — this means a broken or hostile relay |
| unlocked | Touch ID, unchanged; no network involved |
| MCP transport | never blocks: returns `approval_required` with the request id, per `2fa-design.md` §4.5 |

Fail closed throughout: no fallback to "allow" on any error. The escape hatch
is unlocking the screen, which restores the Touch ID path.

---

## 9. Testability

- `SECRETCTL_FORCE_LOCKED=1` exercises the locked branch with the screen
  unlocked. Without it none of this is testable in CI or by hand.
- `SECRETCTL_2FA_ENDPOINT` points the client at a local test server, so the
  e2e suite can run a fake approver that signs verdicts with a test key — full
  protocol coverage, no Cloudflare, no phone.
- `tests/e2e_2fa.sh`: approve, deny, timeout, bad signature, replayed
  `req_id`, wrong `req_id`, unenrolled, grace window expiry. The
  bad-signature and replay cases are the ones that matter — they are what
  keeps the relay untrusted.
- Worker: `vitest` + `@cloudflare/vitest-pool-workers` against `wrangler dev`.

---

## 10. What needs your hands

1. **Cloudflare account** — `wrangler login` is interactive; I cannot do it.
   Also tell me the Worker name / `workers.dev` subdomain, or the custom
   domain if you would rather not use `workers.dev`.
2. **Confirm the plan tier** for Durable Objects (§6.2).
3. **VAPID keypair** — I generate it locally; the private half goes in via
   `wrangler secret put`, which you run.
4. **The iPhone test** in §7.1, before I build out the rest.
5. **Install the PWA to the Home Screen** and grant notification permission,
   then run `secretctl 2fa enroll` and compare fingerprints.

`wrangler` is not installed; `bun 1.3.14` and `node v24.16.0` are, so
`bunx wrangler` works without adding anything global.

---

## 11. Build order

Each step ends somewhere testable, and the riskiest unknown is resolved first.

1. **Spike: payload-less push to your iPhone** (§7.1). Throwaway Worker, no
   secretctl involvement. Decides §7 before anything depends on it.
2. **Mac: lock detection + authorization split.** `lockstate` is written and
   validated; wire it into the unlock path with a stub locked-path approver
   that always denies. Verifiable immediately with `SECRETCTL_FORCE_LOCKED=1`:
   locked ⇒ refuse, unlocked ⇒ Touch ID as before.
3. **Protocol core with a local fake approver.** `p256.zig`, `push_auth.zig`,
   `http.m`, plus `tests/e2e_2fa.sh`. Full protocol including the negative
   cases, no cloud, no phone.
4. **Worker.** Endpoints, DO, VAPID push, static assets. Unit tests against
   `wrangler dev`.
5. **PWA.** Keygen, subscription, service worker, notification actions.
6. **End-to-end on real hardware**, then the enrolment fingerprint check.
7. **Docs**: README section, `usage_text`, and this file updated with whatever
   the real device teaches us.

---

## 12. Open questions

1. **Grace window default** (§6.4). I propose "this request only" as the
   primary action with 5 min as a second tap. If you would rather have 5 min
   be the default action, say so — it is a one-line change but a real
   security/annoyance trade.
2. **Multiple devices**: any one may approve (proposed), versus requiring
   *k*-of-*n*. Any-one is right for one phone; say if you want a second device
   as backup that also counts as a full approver.
3. **Should an unlocked screen ever require push?** Proposed no — Touch ID
   suffices. A stricter mode ("always push, regardless of lock state") would
   be closer to real 2FA in feel, though §1 still applies: it stays a consent
   gate until the key is biometry-bound.
4. **What the phone sees when the description is large** — a `run_with_secrets`
   with twenty tags does not fit a notification. Truncate in the notification
   and show the full list on tap, or summarise counts?
5. **`unknown` lock state** currently fails closed, so an ssh-only session
   always needs phone approval. That is defensible but will be a surprise the
   first time you `ssh` in; confirm you want it.
