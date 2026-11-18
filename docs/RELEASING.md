# Releasing

`pyproject.toml` carries `version`. CI on a pull request and on `main`
checks commit messages and runs the tests. There is no release workflow,
no changelog, and no tag publisher.

Do not push a tag until that workflow exists. A tag pushed today
publishes nothing.
