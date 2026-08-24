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

secretctl mcp                                 # MCP server over stdio
secretctl sync                                # git pull/commit/push the vault
secretctl reveal NPM_TOKEN                    # show plaintext on TTY only
secretctl rm STALE_TOKEN
```

`secretctl --help` lists every command and flag; the binary's help is the
authoritative reference.

## Why

- **Agent-first**: a project-local `.secretctl.toml` allowlist gates
  which secrets reach which commands. Agents cannot inject secrets
  into arbitrary shell commands or read plaintext (`run_with_secrets`
  capability model rather than `get_secret`).
- **Encrypted metadata**: secret names, tags, and timestamps are
  inside the AEAD body. `strings(1)` on the vault file shows nothing
  useful — stronger than SOPS' field-level encryption.
- **Zero ambient state**: no `.env` files, no shell history, no
  process arguments. CLI rejects `secretctl add NAME value`.
- **One binary**: macOS arm64 (Apple Silicon), ~600 KB, no runtime
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
(`SECRETCTL_AGENT_TTL`, default 300s). Inspect it with
`secretctl agent status`, drop the cache with `secretctl agent stop`.

## When the screen is locked

Touch ID needs a finger on the sensor, so with the screen locked there is
nothing to give it — and that is exactly when an agent is most likely to
ask for a secret. `secretctl` detects the lock state before it touches the
keychain or the key cache, and asks a paired phone to approve instead:

```bash
secretctl 2fa enroll     # pair a phone (scan, then confirm the fingerprint)
secretctl 2fa status     # show the paired devices
secretctl 2fa test       # send a test approval request
```

Without a paired device a locked screen simply refuses, and says so. The
MCP server takes the same path, which is the point: it has no way to
prompt for anything, so approval from another device is its only option.

Set `SECRETCTL_FORCE_LOCKED=0` or `=1` to pin the lock state — needed by
every test suite, since otherwise the result depends on whether someone
happens to be looking at the screen.

Approval is a **consent gate**, not a second cryptographic factor:
anything already able to run code as your user can read the vault's wrap
key directly, with or without a phone. `docs/2of2-protector.md` covers
what making it a real factor would take, and what it would cost.

## Status

v0.6.2. macOS arm64 only. Phases 1–5a shipped: vault + CLI, MCP server,
Touch ID–gated unlock, `materialize` + Home Manager module, and
cross-Mac vault sync over git. See `tests/e2e.sh`, `tests/e2e_mcp.sh`,
and `tests/e2e_sync.sh` for the behavior contract.

## License

Apache-2.0
