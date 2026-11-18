# AGENTS.md

Publishes the eight-file feed directory. `libenrich` writes the
threat database, the overlay, and the MaxMind files. `libsigma`
writes the compiled rules and the correlation file. This tree writes
`enrich.json` and runs those programs. The user-agent table and the
public-suffix table are required inputs, not optional feeds.

Read `docs/COMMIT.md` and `docs/BRANCHES.md` before any
commit-shaped or branch-shaped output. You do not commit, push,
or tag. The human does, using those contracts. Work branches are
`<type>/<scope>-<slug>`. Never push `main`.

## Build and test

```
make test
```

Python 3.11 or newer. No third-party packages. `PYTHONPATH` is `src`.

## In

`src/feedset/`, `tests/`, `docs/`, `README.md`, `Makefile`,
`pyproject.toml`.

## Not in

A secret store client. A host, a minion, or a package port.
`feedset build` does not harvest. `ua.json` and `tld.json` arrive as
files or URLs for `build`. `feedset harvest` is the command that
writes them from a Sigma rules directory or from the public SigmaHQ
archive. The committed examples stay fake.

## Must

- The manual is the contract. Change `docs/manual.md` in the same
  write set as the behavior it describes.
- A refused secret, a short threat file, or a bad user-agent or
  public-suffix table does not replace the published generation.
- Paste the command and its output. Do not claim tests passed without
  that paste.
- Secrets stay in the environment. Do not add a command-line flag for
  them. Do not log them.

## Never

- `git commit`, `git push`, `git tag`, `git rebase`, merge, force-push
- Rewrite `docs/COMMIT.md`, `.githooks/`, `scripts/check-commit-msg.sh`,
  or `.github/workflows/` unless that is the write set
- Assistant attribution in comments, commits, or docs
- Em-dashes in anything that ships
- A host name, a deployment, or a package pin in a public commit
