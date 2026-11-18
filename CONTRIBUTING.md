# Contributing

## Commits

`docs/COMMIT.md` is the contract. It is not optional. Install the
hook before you commit:

```
git config core.hooksPath .githooks
git config commit.template .gitmessage
```

PRs squash-merge. The PR title is the subject. The PR body is Why /
Proof / Contract. CI runs `scripts/check-commit-msg.sh` on every
commit in the PR and on the squash on `main`. GitHub's squash
` (#<n>)` suffix is not part of the 72-character subject.

Author email on this repository is jeremie.jourdin@advens.fr.

## Branches

`docs/BRANCHES.md`. Work branches are `<type>/<scope>-<slug>` with
the same type and scope lists as commits. `main` is not a work
branch.

## Issues

Security reports go to jeremie.jourdin@advens.fr, not the tracker.
See `SECURITY.md`.

## Code

Python 3.11, type hints, 4 spaces. `make test` before you ask for
merge. The behavior you change is described in `docs/manual.md` in
the same change.

Do not send a secret-store client or a host integration. `build`
takes `ua.json` and `tld.json` as inputs. `harvest` is the command
that writes them. A sample in this tree stays fake.
