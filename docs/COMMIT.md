# Commit message contract

Every commit in this repository uses this shape. No exceptions: not
the first commit, not a typo fix, not a revert. The hook and CI
reject anything else. GitHub squash-merge uses the PR title as the
subject and the PR body as the rest; those must match this contract
too.

## Shape

```
<type>(<scope>): <subject>

Why:
<one or more lines: the reason the tree changes>

Proof:
<command plus its decisive output, or "not run: <reason>">

Contract: none
```

One blank line after the subject. No extra headers. `Signed-off-by:`
is allowed after `Contract:`. Nothing else.

## First line

- `<type>` is one of: `feat` `fix` `perf` `refactor` `test` `build`
  `ci` `docs` `chore`
- `<scope>` is one of: `cli` `build` `github` `docs` `test`
- `<subject>` is imperative, ASCII, no trailing period, no em-dash
- The whole first line is at most 72 characters. GitHub squash-merge
  appends ` (#<n>)` to the subject on `main`; that suffix is hosting
  metadata and is not counted
- The first line is the only summary. Do not repeat it in Why.

## Why

What problem this commit solves, or what invariant it restores. Not
a file list. Not "update X". If you cannot write Why, the change is
not a commit yet.

A public commit describes the program. It does not name an internal
host, deployment, service, package pin, or port.

## Proof

Paste the acceptance command and the lines that prove the claim. If
the command was not run, the line is `not run: <reason>`. "not run"
without a reason is invalid. Silence is not proof.

## Contract

`none`. This repository does not own a C ABI or an on-disk threat
format. Those stay in `libenrich` and `libsigma`.

## Forbidden in any line

- Tool or assistant attribution (`Co-Authored-By` for an assistant,
  "Generated with", product names of coding agents)
- Em-dash (U+2014) and double-hyphen used as a prose dash
- Trailing subject period
- A type or scope not in the lists above
- An empty Why or Proof section

## Local enforcement

```
git config core.hooksPath .githooks
git config commit.template .gitmessage
git config user.email jeremie.jourdin@advens.fr
```
