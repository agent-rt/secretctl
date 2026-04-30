# secretctl

> Agent-first single-binary secret manager for macOS.

`secretctl` keeps your tokens, API keys, and SSH keys in a single
encrypted file under `~/.secretctl/`. Agents (Claude Code, Codex, …)
get *capability* access — they run commands with secrets injected via
environment variables, but never see plaintext.

```bash
secretctl init                                # passphrase + macOS Keychain
secretctl add OPENAI_API_KEY --tag ai         # TUI (single line)
secretctl add SSH_KEY --tag ssh --editor      # $EDITOR (multi-line)
secretctl edit OPENAI_API_KEY                  # rotate via $EDITOR

secretctl list --json                         # name+tags only, no value
secretctl exec --tag ai -- python main.py     # env-injected, audited
secretctl render .npmrc.tmpl --out ~/.npmrc   # ${NAME} substitution

secretctl reveal NPM_TOKEN                    # show plaintext on TTY only
secretctl rm STALE_TOKEN
```

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
- **One binary**: macOS arm64+x86_64, ~600 KB, no runtime
  dependencies (Security.framework + libc are system-provided).

## Install

```bash
brew install agent-rt/tap/secretctl
```

Or download the tarball for your arch from the
[Releases page](https://github.com/agent-rt/secretctl/releases).

## Status

v0.1.0 — Phase 1 MVP. macOS only. See `tests/e2e.sh` for behavior
contract. Phase 2+ will add MCP server, Touch ID protector, NixOS
materialize hook (in priority order).

## License

Apache-2.0
