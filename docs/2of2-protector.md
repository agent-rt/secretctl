# Two-of-two protector: making the second factor cryptographic

Status: **design, awaiting confirmation. No code written.** 2026-08-24.
Implements `2fa-design.md` §4.2, which two measurements promoted from an
option to a prerequisite.

---

## 1. Why, in two sentences each

**The security reason.** Protectors are a disjunction — `master_key.zig:186`
walks the list and the first one that unwraps wins — so today
`mk = passphrase OR keychain`, and M3 showed the keychain half needs only "can
run code as this uid" because its wrap key reads out with interaction
explicitly forbidden. An agent on this Mac already holds that, so the vault is
one factor away from a program whose whole job is to run unattended.

**The operational reason, measured 2026-08-24.** With the screen locked, a
Touch-ID-gated keychain protector cannot produce the master key even after a
phone has approved — it fails in 13 s (`2fa-push-approval.md` §2.2b). A consent
gate and a biometric gate are mutually exclusive while locked, because the
finger one needs is unavailable in exactly the situation the other exists for.
That leaves two choices: drop the biometric gate, or make approval *release a
key share* so approval **produces** the key instead of authorising a step that
cannot then be satisfied. This document is the second.

| | locked approval | at-the-desk biometric gate | wrap key alone is enough? |
|---|---|---|---|
| keychain, no Touch ID gate | works (measured) | given up | yes — M3 |
| keychain + Touch ID gate | **fails** (measured) | works | yes — M3 |
| **2-of-2 (this doc)** | works | works | **no** |

---

## 2. The construction

New `ProtectorType.two_of_two = 5`. Values 1–3 are taken; 4 is skipped to leave
room for the `age_identity` work already numbered 3.

```
S_mac    32 random bytes, in this machine's keychain
S_2nd    32 random bytes, held by the second factor (§3)

K   = HKDF-SHA256(salt = protector_id,
                  ikm  = S_mac ‖ S_2nd,
                  info = "secretctl 2of2 v1")
mk  = AES-256-GCM-open(K, nonce, aad = mk_id ‖ protector_id, ct, tag)
```

Neither half reveals anything alone: `S_mac` without `S_2nd` derives a `K` that
fails the GCM tag, and vice versa.

**AEAD over the joined shares rather than `mk = S_mac XOR S_2nd`.** XOR would
work cryptographically but produces a wrong `mk` silently, which then fails
downstream at the file HMAC (`master_key.zig:235`) — an error that reads as
vault corruption. The tag here authenticates both shares, so a missing or wrong
half is reported as an authentication failure at the protector, next to its
cause. This is the same reasoning that put the tag in the sealed-envelope
format.

### 2.1 Body layout

Following the §3.1 common header (`protector_len`, `protector_id`,
`protector_type`, `created_at`, `body_len`):

```
  "T2"                    2   magic, distinct from "S2" keychain bodies
  flags                   1   bit0: S_2nd source is a phone (§3.2)
                              bit1: S_2nd source is a passphrase (§3.1)
  kc_service_len          2   u16 LE
  kc_service              n   "secretctl"
  kc_account_len          2   u16 LE
  kc_account              n   hex(mk_id) ‖ "-2of2", so a 2of2 share never
                              collides with a plain keychain protector's item
  mk_nonce               12
  mk_ct_len               2   u16 LE  (32)
  mk_ct                  32   AES-256-GCM over mk, keyed by K
  mk_tag                 16
  -- present only when flags bit1 (passphrase-held S_2nd):
  argon2_m_kib            4   u32 LE
  argon2_t                4   u32 LE
  argon2_p                4   u32 LE
  argon2_version          4   u32 LE
  salt_len                2   u16 LE
  salt                   16
  s2nd_nonce             12
  s2nd_ct_len             2   u16 LE  (32)
  s2nd_ct                32   AES-256-GCM over S_2nd, keyed by argon2id
  s2nd_tag               16
```

Argon2id parameters come from `argon2.zig`: m = 65536 KiB, t = 3, p = 1,
version 0x13. They are persisted per protector, as the existing passphrase
protector already does, so changing the defaults never locks out a vault.

Both AEAD operations bind `aad = mk_id ‖ protector_id`, matching
`keychain.zig:buildAad`, so a protector body cannot be transplanted between
vaults or between protector slots.

---

## 3. Where the second share lives

Three sources, distinguished by `flags`. A vault may carry several 2of2
protectors — one per (machine, source) pair — and they remain a disjunction
*among themselves*. That is fine: each one still requires two things.

### 3.1 Passphrase-held (`flags` bit1)

`S_2nd` sits in the protector body, wrapped under `argon2id(passphrase)`. Real
2-of-2 with no phone, no network, no new infrastructure: unlocking needs the
keychain **and** the passphrase.

This is the cheapest correct configuration and the right default for a machine
that is used at the desk. It does not solve the locked-screen case, because
nobody is there to type.

### 3.2 Phone-held (`flags` bit0) — the locked-screen case

`S_2nd` is generated during setup, handed to the phone once, and stored **on the
phone** (IndexedDB, alongside the device keys). Neither this machine nor the
relay keeps a copy.

On approval, the phone returns `S_2nd` **sealed to a per-request key the client
generated**, so the relay carries an opaque blob and never learns the share:

- the client puts `reply_pk` — a fresh ECDH P-256 public key, generated for this
  request only — inside the request envelope, which is already sealed to the
  device. The relay cannot read it, and it cannot substitute one either, since
  the envelope is AEAD-protected and the request is signed.
- the phone seals `S_2nd` to `reply_pk` using the same construction as the
  request envelope, with `info = "nudge-share-v1"`.
- the verdict carries the sealed share. The client opens it with the matching
  private key, which never left memory.

Per-request ephemeral, so no long-term client sealing key is needed and a
captured share blob is useless for the next request.

**Verdict canonical string gains a version.** The share must be covered by the
device's signature, or a relay could strip it (the client then cannot unlock —
detectable but confusing) or swap it (the AEAD then fails — also confusing).
Covering it turns both into a signature failure, which is the legible outcome:

```
nudge-verdict-v2 ‖ req_id ‖ verdict ‖ grace_s ‖ ts ‖ sha256(sealed_share or "")
```

v1 stays accepted for verdicts with no share, so the deployed `nudge` and the
current client keep working during the transition.

### 3.3 Recovery share (`flags` = 0)

`S_2nd` is printed once, as BIP39 words or Crockford base32, and never stored
anywhere by this machine. Typed in when needed.

This is **deliberately a 1-of-N escape hatch in disguise**: whoever holds the
recovery words plus the machine's keychain can unlock. Its entire purpose is
surviving the loss of the phone or the passphrase, so it must live offline —
paper, or a password manager on a different device. The security claim of the
whole scheme is therefore "2-of-2 for day-to-day use, with an offline recovery
secret", and stating it any more strongly would be false.

---

## 4. The migration is where the security actually happens

**A 2of2 protector added alongside the existing ones changes nothing.** The
protector list is a disjunction, so leaving the standalone `passphrase` or
`macos_keychain` entries in place means either still unlocks on its own and the
conjunction is theatre.

So `secretctl key upgrade-2of2` must, in one atomic rewrite of `master.key`:

1. unlock with the current protectors,
2. generate `S_mac` (into the keychain) and `S_2nd` (per §3),
3. write the 2of2 protector,
4. write a recovery protector and **print its words once**,
5. **remove the standalone passphrase and keychain protectors**,
6. verify the new file unlocks with `S_mac + S_2nd` *before* replacing the old
   one — `fsx.writeAllAtomic` gives the atomic swap, and a verify-before-swap is
   what keeps a bug from producing an unopenable vault.

Step 5 is the one that must not be skippable, and step 6 the one that must not
be optional. A `--keep-single-factor` flag is deliberately **not** offered:
anyone who wants that already has today's behaviour by not upgrading.

`secretctl key show-protectors` should print the resulting set plainly, because
"is my vault actually 2-of-2?" must be answerable without a hex dump.

---

## 5. Unlock flow

`master_key.zig` gains one `switch` case. The ordering question from
`2fa-push-approval.md` §2.2 does not change: `authz.decide()` still runs above
the agent cache and the keychain.

```
locked screen, phone-held 2of2:
  authz.decide() -> out_of_band
  push_auth.requestApproval(purpose)      -> verdict + sealed share
  open sealed share with reply_sk          -> S_2nd
  read S_mac from the keychain             -> no biometric gate involved
  K = HKDF(...); mk = AEAD-open(...)
  cache mk in the agent for grace_s        -> unchanged from today
```

Grace windows need no new concept: the agent already caches `mk`, which is
strictly more sensitive than a share, so caching `mk` for `grace_s` is what it
already does.

Note what disappears: **there is no `local_auth.evaluate` on this path.** That
is the whole point — the biometric gate was what could not be satisfied while
locked, and here approval itself supplies the missing half.

At the desk with a passphrase-held 2of2, the biometric gate can stay on the
`S_mac` keychain item for the usual reason (a visible prompt before the vault
opens), and it works because a finger is available.

---

## 6. Failure modes

| Condition | Behaviour |
|---|---|
| phone lost, passphrase 2of2 also present | unlock with keychain + passphrase |
| phone lost, no other 2of2 | recovery words + keychain; then re-enrol |
| keychain item deleted (e.g. `prune-keychain` with a stray `$SECRETCTL_HOME`) | `S_mac` gone → recovery words alone are **not** enough. Documented loudly; see §7 |
| passphrase forgotten, phone present | phone-held 2of2 still unlocks |
| relay strips the sealed share | signature over `sha256(share)` fails → refused as a forged verdict |
| relay substitutes a share | same signature failure, not a silent wrong key |
| approval times out | denial, as today |
| a second machine still on 1-of-N | the weakest machine sets the level (§7) |

Row 3 deserves emphasis: with 2-of-2, losing `S_mac` is as fatal as losing the
other half, and the earlier `prune-keychain` incident in this project deleted
exactly that kind of item. That command needs the guard already recorded as
`2fa-design.md` §5 item 6 **before** 2of2 ships, not after.

---

## 7. Multi-machine

`S_mac` is per machine, so each Mac needs its own 2of2 protector. The vault
syncs over git (`secretctl sync`), so all of them travel in `master.key`.

The disjunction across protectors means **the weakest machine sets the level**:
one Mac left on a standalone keychain protector makes the whole vault 1-of-N for
anyone who has that Mac. `upgrade-2of2` therefore has to be run on every machine
before the claim holds, and `show-protectors` should say so when it sees a
standalone protector next to a 2of2 one.

`healKeychainProtector` (`cli.zig:359`) already carries a note that it drops
*all* keychain protectors and adds one for the current machine. That is wrong
once per-machine 2of2 protectors coexist, and must be fixed as part of this
work rather than left as a comment.

---

## 8. Testability

- **`SECRETCTL_2ND_SHARE_FD`** — read `S_2nd` from a dedicated fd, so the whole
  2of2 path is testable with no phone and no network, the same way
  `SECRETCTL_PASSPHRASE_FD` made batch mode testable. Argv is not an option for
  a key share, for the reason already established: `ps` is world-readable.
- **Negative cases that must exist**, since a conjunction that silently accepts
  one half is indistinguishable from a working one: `S_mac` alone refused,
  `S_2nd` alone refused, either half corrupted refused, a share from a
  *different* protector refused (the `aad` binding), and a 2of2 vault refusing
  to unlock after the standalone protectors are removed but with only one half
  supplied.
- **A migration test that asserts what was removed**, not only what was added:
  after `upgrade-2of2`, unlocking with the passphrase alone must fail. That is
  the assertion that catches §4 being skipped.
- **Cross-language** for the sealed share, mirroring `e2e_seal_xlang.sh`: the
  phone seals, this client opens. The direction that broke last time was the
  untested one.

---

## 9. Open questions

1. **Does the phone-held share belong in the same PWA as approval?** It makes
   the phone a key holder rather than a consenting party, so losing the phone
   escalates from "cannot approve" to "cannot unlock without recovery words".
   The alternative — phone approves, passphrase supplies the share — keeps the
   phone stateless but needs someone at a keyboard, which defeats the locked
   case. Proposed: yes, with §3.3 recovery mandatory at setup.
2. **Recovery encoding**: BIP39 words are transcribable by voice and check-summed;
   Crockford base32 is shorter and already used for pairing codes. Proposed:
   BIP39, because this is written down once and read back under stress.
3. **Should `upgrade-2of2` be reversible?** A `downgrade` command is easy and
   makes the scheme less frightening to adopt; it is also a one-command way to
   quietly return to 1-of-N. Proposed: offer it, print what it gives up, and
   record it in the audit log.
4. **Does the agent cache need a shorter TTL under 2of2?** The cached `mk`
   bypasses both factors for its window, which matters more when the factors are
   real. Proposed: keep the existing TTL but log the cache hit, so the audit
   trail shows which unlocks required approval and which did not.

---

## 10. Build order

1. **`p256.zig` gains nothing; `argon2`/`hkdf`/AEAD are already in place.** Start
   with the protector: format, wrap, unwrap, and the negative tests, with
   `S_2nd` supplied from an fd. No phone, no network, no migration.
2. **`upgrade-2of2` and `show-protectors`**, including the verify-before-swap and
   the migration test that asserts the standalone protectors are gone.
3. **Recovery share**: generation, encoding, and an unlock test that uses only
   the words plus the keychain.
4. **`prune-keychain` guard** (`2fa-design.md` §5 item 6) — before phone-held
   shares exist, because by then `S_mac` is load-bearing.
5. **nudge protocol v2**: `reply_pk` in the envelope, sealed share in the
   verdict, `nudge-verdict-v2` canonical string, and the cross-language test.
6. **Phone-held share end to end** on hardware, locked screen.
7. **`healKeychainProtector`** fixed for per-machine protectors, and §7's
   warning in `show-protectors`.

Steps 1–4 need no phone and no service, and they are where the security
actually lands. Step 5 onwards is what makes the locked-screen case work.
