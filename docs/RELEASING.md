# Versioning and releases

Written after the same mistake twice: `0.8.2` and `0.10.0` were both bumped into
existence by a feature branch and then bumped past before anything shipped, so
neither version ever existed. This document is the rule that prevents it.

## The rule

**A feature branch never touches a version string.** The bump is part of
releasing, not part of building.

That is the whole rule, and it is the one that was being broken. Bumping in a
feature PR means the number is a guess about which release the change will land
in — and the moment two PRs merge before a tag, one of those guesses is wrong
and a version number is skipped.

## Where the version lives

Three places, and they must agree:

| file | what it is |
|---|---|
| `flake.nix` | what Nix builds |
| `src/cli.zig` | what `--version` prints |
| `README.md` | the Status section |

`build.zig.zon`'s `.version` is **vestigial** — it has read `0.1.0` since the
beginning and nothing consumes it. Leave it alone; changing it would imply it
means something.

## Choosing the number

Pre-1.0, so the middle number carries everything user-visible:

- **`0.X.0`** — any change to the surface: a new command, a removed command, a
  changed default, a different output format. Removals and additions both land
  here, because pre-1.0 does not promise to distinguish them.
- **`0.X.Y`** — fixes and documentation only. Nothing a caller could notice
  except that something stopped being wrong.

If a release contains both, it is `0.X.0`.

## Doing a release

1. Merge the feature PRs. None of them touched a version. If they form a
   stack, merge it atomically — see below.
2. Branch `release/vX.Y.Z`.
3. Bump the three strings. That commit is the only thing on the branch.
4. PR, wait for CI, merge.
5. `git tag vX.Y.Z <merge commit>` and push the tag. Lightweight, matching every
   previous tag — the repo has `tag.gpgsign` set but nothing here is actually
   signed (jj creates the commits and does not honour git's signing config), so
   a signed tag would be inconsistent with its own history. Use
   `git -c tag.gpgsign=false`.
6. `release.yml` fires on the tag: builds ReleaseSafe, publishes to the project
   and tap releases, and pushes an updated `Formula/secretctl.rb` **directly**
   to the tap.

Then verify what was actually published rather than trusting the green tick:
download the tarball, check its SHA-256 against the formula, extract it and run
`--version`. A workflow can succeed and still ship the wrong bytes.

## Merging a stack

Several dependent PRs are a stack, and `gh pr merge` cannot merge one: merging
them one at a time re-targets the others and churns their CI.

```bash
gh stack merge <stack#> --yes --rebase   # all of them, or none
gh stack sync --prune                    # delete the merged local branches
```

`gh stack` is git-branch-centric and this repo is driven with jj, which keeps
HEAD detached and presents the working copy's contents as uncommitted changes.
Every `gh stack` command fails on both counts until you do this first:

```bash
jj new <branch>          # @ becomes empty, so git's worktree matches HEAD
git checkout <branch>    # attach HEAD
```

Afterwards `jj git fetch` re-imports and the stack is intact.

One trap worth knowing: if `gh stack init` fails partway through its checkout,
**the stack has already been registered**. Rerunning then reports
`branch "X" already exists in a stack`, which reads like nothing was created.
Attach HEAD and run `gh stack view --json` — that is the only reliable view.

## Getting confirmation first

Pushing the tag is the irreversible, outward-facing step — it rewrites the tap
formula and changes what `brew upgrade` installs for anyone. **Ask before
pushing a tag.** Merging PRs does not need asking; tagging does.

## Consequences to expect after a release

Every build is ad-hoc signed, so the cdhash changes and the keychain item's
trusted-app ACL goes stale. The first vault use after `brew upgrade` asks for
the master password once, then re-establishes the protector. This is normal and
documented in `2fa-design.md` §1.1; it is not a sign that something broke.

The TOTP seed's keychain item survives this — measured across 0.8.0 → 0.8.1 —
so an upgrade does not cost a re-enrolment.
