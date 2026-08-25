# secretctl

> Agent-first single-binary secret manager for macOS.

`secretctl` keeps your tokens, API keys, and SSH keys in a single
encrypted file under `~/.secretctl/`. Agents (Claude Code, Codex, …)
get *capability* access — they run commands with secrets injected via
environment variables, but never see plaintext.

```bash
secretctl init                                # passphrase + Touch ID keychain
secretctl add OPENAI_API_KEY --tag ai         # prompt (single line, masked)
secretctl add SSH_KEY --tag ssh --editor      # $EDITOR (multi-line)
secretctl add APNS_KEY --file AuthKey.p8      # exact bytes (also --stdin)
secretctl edit OPENAI_API_KEY                 # rotate via $EDITOR
secretctl tag OPENAI_API_KEY ai,prod          # replace tags, no re-encrypt

secretctl list --json                         # name+tags only, no value
secretctl exec --tag ai -- python main.py     # env-injected, audited
secretctl render .npmrc.tmpl --out ~/.npmrc   # ${NAME} substitution
secretctl materialize SSH_KEY --out ~/.ssh/id_ed25519 --mode 0600

secretctl sync                                # git pull/commit/push the vault
secretctl reveal NPM_TOKEN                    # show plaintext on TTY only
secretctl rm STALE_TOKEN
```

`secretctl --help` lists every command and flag; the binary's help is the
authoritative reference.

## Why

- **Agent-first**: a project-local `.secretctl.toml` allowlist gates
  which secrets reach which commands. An agent runs
  `secretctl exec --tag ai -- <allowlisted command>` and the secrets
  arrive in the child's environment; it never handles plaintext itself,
  and it cannot widen the allowlist from outside the file.
- **Encrypted metadata**: secret names, tags, and timestamps are
  inside the AEAD body. `strings(1)` on the vault file shows nothing
  useful — stronger than SOPS' field-level encryption.
- **Zero ambient state**: no `.env` files, no shell history, no
  process arguments. CLI rejects `secretctl add NAME value`.
- **One binary**: macOS arm64 (Apple Silicon), ~900 KB, no runtime
  dependencies (Security.framework + libc are system-provided).

## Install

```bash
brew install agent-rt/tap/secretctl  # macOS arm64 (Apple Silicon) only
```

Or download the tarball from the
[Releases page](https://github.com/agent-rt/secretctl/releases).

### Nix / Home Manager

The flake builds from source via `zig-overlay` — no tarball, no
`sha256` to keep in sync. It exposes `packages.default`,
`overlays.default` (attaches `pkgs.secretctl`), and
`homeManagerModules.default`:

```nix
inputs.secretctl.url = "github:agent-rt/secretctl";

programs.secretctl = {
  enable = true;
  envSecrets.API_TOKEN = { };                         # -> ~/.config/secretctl/env.sh
  fileSecrets.SSH_KEY = { path = ".ssh/id_ed25519"; mode = "0600"; };
  agent.enable = true;                                # sets $SECRETCTL_AGENT
};

programs.zsh.initExtra = "source ~/.config/secretctl/env.sh";
```

The module is a declarative wrapper around `secretctl materialize` that
runs at *activation* time — nothing is decrypted during Nix evaluation.
It assumes `secretctl init` has already run and the secrets exist in the
vault. See `nix/home-manager.nix` for all options.

Homebrew and Nix are independent update tracks: bumping one does not
move the other.

## Touch ID and the key cache

`init` installs a Touch ID–gated Keychain protector by default
(`--no-touch-id` opts out). Two commands exist for when that protector
drifts out of sync with the binary:

```bash
secretctl reinstall-keychain     # rebuild the protector for the current binary
secretctl prune-keychain         # list stale items from old vaults; --yes to delete
```

A re-signed binary invalidates the trusted-app ACL, so an upgrade can
make the Keychain start prompting. `secretctl` self-heals this on read
since v0.6.1; `reinstall-keychain` is the manual escape hatch.

On a second Mac sharing the vault over `secretctl sync`, run
`secretctl key add-keychain-protector` once to add that machine's own
keychain unlock path. The vault header holds a list of protectors: the
passphrase, plus one keychain entry per machine.

To avoid one Touch ID prompt per command, set `SECRETCTL_AGENT=1` — a
background agent caches the unlocked master key with a sliding TTL
(`SECRETCTL_AGENT_TTL`, default 120s). Inspect it with
`secretctl agent status`, drop the cache with `secretctl agent stop`.

`reveal` does **not** use the cache — it hands plaintext straight to
whoever asked, so it always costs a fresh Touch ID (or a TOTP code while
locked). Cached unlocks are recorded in the audit log as `unlock.cached`, so
afterwards you can tell which unlocks a human authorized from which ones the
cache served for free.

`exec`, `render` and `materialize` do still use the cache. That is a
deliberate trade, not an oversight — they are the bulk of normal use, and
excluding them would mean a prompt every time. It also means
`secretctl exec --tag t -- env` remains an unprompted path to plaintext
while the cache is warm; a short TTL is what bounds that.

## When the screen is locked

Touch ID needs a finger on the sensor, so with the screen locked there is
nothing to give it — and that is exactly when an agent is most likely to
ask for a secret. `secretctl` detects the lock state before it touches the
keychain or the key cache, and asks for a TOTP code instead:

```bash
secretctl 2fa enroll     # prints a scannable QR, and the otpauth:// URI
secretctl 2fa status     # enrolled? which code was last spent?
secretctl 2fa disable    # forget the seed; a locked screen goes back to refusing

# The code goes on its own fd, never argv — `ps` is world-readable.
SECRETCTL_TOTP_FD=3 secretctl 2fa test 3<<<"123456"
SECRETCTL_TOTP_FD=3 secretctl list 3<<<"123456"
```

`enroll` draws the QR in the terminal, so there is no step where you have
to turn a URI into a code yourself — which is where enrolment actually goes
wrong. The URI is printed underneath and is the source of truth; if the
terminal is too narrow the QR is skipped and says so.

**Fully offline.** No service to run, no relay to trust, nothing to reach
over the network. Standard RFC 6238 (SHA-1, 6 digits, 30s), so any
authenticator works — 1Password, Raivo, Google Authenticator, whatever you
already have.

The intended flow is that an agent asks, you read six digits off your
phone, and you hand them over on the fd. Without an enrolment a locked
screen simply refuses, and says so.

*Google Authenticator quirk:* after scanning it may show no confirmation,
which looks like the scan failed. Close and reopen the app before trying
again — the entry is usually there, and rescanning just adds duplicates
that generate identical codes.

Each code is **single use**: `secretctl` records the time step it spent and
refuses that code again, with a message that distinguishes "wrong code"
from "that one is gone, wait 30s". This matters because the code travels
through whatever channel you used to hand it over — a chat window, a
terminal someone can scroll back through.

### One code buys 120 seconds

```bash
secretctl 2fa auth 123456    # opens a 120s window
secretctl 2fa revoke         # closes it early
secretctl 2fa status         # shows whether one is open, and how long is left
```

Without this, every command run while locked needs its own fresh code, and
codes roll every 30s — workable for one secret, painful for a sequence.

**This is a deliberate hole, bounded.** For those 120 seconds a locked screen
authorizes local commands with no further confirmation, which is exactly what
the authorization check sitting above the key cache otherwise prevents. It is
short so that walking away closes it soon; the deadline is absolute, so
suspending the machine does not extend it; `revoke` closes it immediately; and
every use is written to the audit log as `authz.window_used` with the time
remaining, so afterwards you can tell which unlocks a human authorized from
which the window covered.

The code that opens a window is spent like any other — a window is not a way to
reuse one.

Unlike the master passphrase, the code may go on the command line. It is
single-use, expires in 30s, and is consumed by the command carrying it, and in
the flow this exists for it has already travelled through a chat window; `ps` is
not the weak link. `secretctl 2fa auth` with no argument reads it from
`$SECRETCTL_TOTP_FD` or the terminal instead.

### One code per command, without a window

The key cache does **not** shorten this. Measured, with the cache warm:

```
give a code            -> unlocks
same command, no code  -> refused: screen is locked
same code again        -> refused: already used
next code              -> unlocks
```

The authorization check runs *above* the cache deliberately — otherwise
locking the screen would leave a 120s window needing no approval at all,
which is the hole the check exists to close. Combined with single-use
codes, that means **every command run while locked needs its own fresh
code**, and codes roll every 30s.

For the usual case — an agent needs one secret, you hand over one code —
this is fine. For a sequence of commands it is not: you would be feeding
codes one at a time with a wait between each. Do the work in a single
`secretctl exec` instead; that is what it is for, and it costs one code.

That was the behaviour before `2fa auth` existed, and it is still what you
get without one. The window above is the answer to it, with its cost stated
rather than hidden.

Set `SECRETCTL_FORCE_LOCKED=0` or `=1` to pin the lock state — needed by
every test suite, since otherwise the result depends on whether someone
happens to be looking at the screen.

A TOTP code is a **consent gate**, not a second cryptographic factor — six
digits carry ~20 bits, so a code can never be key material, and verifying
one needs the seed stored locally. What that does and does not mean,
measured rather than assumed:

- A process that is not `secretctl` **cannot** read the vault's wrap key.
  The keychain item's ACL names one binary; anything else gets
  `errSecAuthFailed`, or a dialog if it allows interaction.
- What it can do is *ask* `secretctl`, and then it meets the same gates you
  do. With the screen locked that means a TOTP code. It cannot mint one
  either: the seed lives under the same ACL as the wrap key.
- The gap: with the screen **unlocked and the key cache warm**
  (`SECRETCTL_AGENT=1`), a local caller can get a secret through `exec` with
  no prompt at all. `reveal` is excluded from the cache, so it always
  costs fresh authorization — but `exec` is not, which narrows the gap
  rather than closing it. The TTL (default 120s) is what bounds it;
  `SECRETCTL_AGENT=0` closes it at one prompt per command.

`docs/2fa-design.md` §1 carries the measurements; `docs/2of2-protector.md`
specifies a real second factor and records why it is not being built.

## Status

v0.9.0. macOS arm64 only. Shipped: vault + CLI, Touch ID–gated unlock,
`materialize` + Home Manager module, cross-Mac vault sync over git, and
offline TOTP approval when the screen is locked. See `tests/e2e.sh`,
`tests/e2e_sync.sh`, and `tests/e2e_lockstate.sh` for the behavior
contract.

**The MCP server was removed in v0.7.0.** If you were running
`secretctl mcp`, point the agent at the CLI instead: `secretctl exec`
covers the same capability model — the `.secretctl.toml` allowlist is
enforced there too, so nothing about which secrets reach which commands
changes. `list`, `exec` and the allowlist were what the three safe tools
wrapped; `get_secret` has no CLI equivalent by design, and `reveal` is
TTY-only.

The locked-screen path is verified end to end in `tests/e2e_lockstate.sh`,
including a real unlock with a code generated by an independent
implementation — which is what proves an authenticator app's codes are the
codes this accepts.

## License

Apache-2.0
