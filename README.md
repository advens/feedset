# feedset

Build the directory an enricher and a Sigma matcher read. The
manual is [docs/manual.md](docs/manual.md). Read it before changing
the command or the config.

The directory has eight names. They move in two generations. A
generation that fails leaves its previous files in place.

| File | Generation | What it is |
|---|---|---|
| `threat.thrt` | enrich | Threat database. `enrich sync --apply` writes it when the pull returns at least one attribute. `enrich build` writes it again. |
| `threat.thrt_overlay` | enrich | Whitelist, tag, or add list (`.ovly`). `enrich build` writes it. `enrich sync --full` also writes it when the pull returns at least one attribute. |
| `GeoLite2-City.mmdb` | enrich | MaxMind City. |
| `GeoLite2-ASN.mmdb` | enrich | MaxMind ASN. |
| `ua.json` | detect | User-agent table. A JSON object with a non-empty `entries` array. A row from `harvest` has `ua`, `class`, and `label`. |
| `tld.json` | detect | Public-suffix table. Same check as `ua.json`. A row from `harvest` has `tld`, `class`, and `label`. |
| `rules.sigmac` | detect | Compiled Sigma rules. |
| `rules.corr.json` | detect | Correlation file from the same compile. |

The user-agent table and the public-suffix table are part of the
detect generation, with the compiled rules. `build` does not make
them. A local `path` is copied. A `url` is stored by `enrich fetch`.
`sigmac` runs only after both tables have been checked. On success
the four detect files are published together.

`feedset harvest` is a separate command. It writes `ua.json`,
`tld.json`, and a one-line `PIN` into `harvest.dest` from a Sigma
rules directory, or from the public SigmaHQ archive. Point `ua.path`
and `tld.path` at `<dest>/ua.json` and `<dest>/tld.json` when the
next `build` should copy those files. A `url` on `ua` or `tld` is a
different source. The [manual](docs/manual.md) section `harvest` is
the contract for the walk, the stamp, and `--check`.

`libenrich` owns `.thrt`, `.ovly`, and the MaxMind download.
`libsigma` owns `.sigmac` and the correlation file. `feedset` writes
the enrich config, runs those two programs, and publishes the eight
names.

```
make test
make example
```

Python 3.11 or newer. No third-party packages.

`make example` stages `docs/examples/` in a temporary directory,
runs `render`, then `build --only detect`. It does not run
`harvest`, and the staged config has no `harvest` block. The
`harvest` block in `docs/examples/feedset.json` shows the field
names, with paths under `/var/lib`, like the other paths in that
file. `docs/examples/sigma/` is a sample rules tree for
`harvest.rules`. The shipped `ua.json` and `tld.json` are
hand-written. Harvesting `sigma/` does not reproduce them: the
sample rules put `ExampleBot/1.0` in class `malware`, omit
`FeedsetSample/0.1`, mark the suffix `test` as `suspicious`, and
also write `ExampleBot` as `contains`, `ExampleMine` as `prefixes`,
and `ExampleEnd` as `suffixes`.
The threat inputs are indicator files: a CSV, a plain-text list, a
dictionary, a STIX bundle, and a saved MISP body. The values are
documentation addresses (RFC 5737, RFC 3849), RFC 2606 names, one
documentation URL, one documentation mailbox, and hashes of the
right width filled with zeroes. `render` writes each file as a `path` feed in
`enrich.json`. Compiling those feeds into `threat.thrt` is
`enrich build`, and this run does not invoke it. The printed
`publish` directory holds the detect generation (`ua.json`,
`tld.json`, `rules.sigmac`, `rules.corr.json`). The two rule files
come from the `sigmac` stand-in. Do not point a collector at that
directory. `docs/examples/README.md` lists every sample.

## Commands

```
feedset harvest -c /var/lib/feeds/feedset.json
feedset harvest -c /var/lib/feeds/feedset.json --check
feedset render  -c /var/lib/feeds/feedset.json
feedset build   -c /var/lib/feeds/feedset.json
feedset build   -c /var/lib/feeds/feedset.json --full
feedset build   -c /var/lib/feeds/feedset.json --only enrich
feedset build   -c /var/lib/feeds/feedset.json --only detect
```

`harvest` reads the optional `harvest` block. Set `dest`, and set
exactly one of `rules` or `ref`. `rules` is an absolute Sigma rules
directory and opens no connection. `ref` is `refs/heads/<name>`,
`refs/tags/<name>`, or 40 hex digits. With `ref`, the command
downloads `https://github.com/SigmaHQ/sigma/archive/<ref>.tar.gz`
and asks `https://api.github.com` which commit that ref is. The
request user agent is `feedset/0.1.0`.

`PIN` records what was read. For `rules` it is `sha256:` over every
`.yml` and `.yaml` file, in path order. Each file contributes its
relative path, a NUL, its bytes, and a NUL. For `ref` it is the
commit. When that lookup fails, `PIN` is the `sha256:` of the YAML
that was extracted, and a later `--check` on that `ref` does not
accept it.

`--check` prints nothing and writes nothing. For `rules` it hashes
the directory again. For `ref` it asks for the commit the ref points
to now, and it does not download the archive. Exit 0 means `PIN`
matches. Exit 1 means the stamp differs or the lookup failed. A
missing block, a refused archive, and an empty table are also exit
1, and those last two belong to the writing command. Exit 75 means
the lock is busy. `render` and `build` do not run `harvest`.

A written table is UTF-8 JSON, mode `0644`, keys sorted. It has
`schema` 1, `product` (`feedset-ua` or `feedset-tld`), `built_at`
in UTC, `classifiers`, and a non-empty `entries` array. A `ref`
harvest also writes `sigmahq_ref`, and `sigmahq_commit` when the
commit was found. User-agent classes from this command are
`malware` (the title or the file name contains `malware`) and
`suspicious`. An exact row has no modifier and is at least 3 bytes.
`contains`, `startswith`, and `endswith` of at least 5 bytes are
written to `contains`, `prefixes`, and `suffixes`, unless the value
occurs in a normal `Mozilla/5.0` browser User-Agent. `|re` and any
other modifier are dropped. Suffix classes are `common` and
`suspicious`. The classifiers describe the table. `empty` and
`encoded` are listed on `ua.json` only when a rule contributed that
case. `tld.json` always lists `uncommon`, which is not itself a
row. `build` accepts a
hand-written table that uses other class names. It checks that the
file is a JSON object of at most 32 MiB, that `entries` is a
non-empty array, and that `classifiers` is an array when present.
It does not check `class`.

`render` reads `feedset.json` and the three environment variables
below. It writes `enrich.json` mode `0600`. A refused secret does
not replace an existing `enrich.json`.

`build` publishes into the `publish` directory. `enrich sync` always
runs with `--full`, since the `enrich build` that follows recompiles
the MISP file; the `--full` flag of `build` is accepted and changes
nothing. `--only`
runs one generation. `harvest` and `build` share one lock.

Secrets, in the environment, never in `feedset.json` and never on
the command line:

```
MISP_KEY
MAXMIND_ACCOUNT_ID
MAXMIND_LICENSE_KEY
```

Both MaxMind values are set, or `render` refuses the file. One of
them set is an error. The MISP key is required.

## What a failure leaves behind

The publish directory is the promise. `enrich` still writes its own
work files when a command succeeds.

- `render` exits before the replace when a secret, a path, or a feed
  row is refused. The previous `enrich.json` stays.
- `enrich sync`, `enrich build`, or `enrich fetch` exits non-zero:
  the enrich generation is not published.
- `threat.thrt` under `min_thrt_bytes`: the enrich generation is not
  published.
- A missing or empty City or ASN database after fetch: the enrich
  generation is not published.
- `ua.json` or `tld.json` missing, empty, or without a non-empty
  `entries` array: the detect generation is not published. `sigmac`
  is not started.
- `sigmac` exits non-zero, or either output is empty: the detect
  generation is not published.
- A second `build` or `harvest` that cannot take the lock exits 75.
  It does not start `enrich`, `sigmac`, or a download.
- `harvest` refuses the archive, or either table has no rows, before
  the first replacement: the previous `ua.json`, `tld.json`, and
  `PIN` stay.
- `harvest` then replaces `ua.json`, then `tld.json`, then `PIN`.
  A failure between those three can leave a mix.
- `harvest --check` writes nothing. A different stamp or a failed
  commit lookup exits 1.
- A crash while a generation is being renamed into `publish` can
  leave a mix of old and new names. The next successful publish of
  that generation replaces the names it owns.

The enrich generation and the detect generation are independent. One
can publish while the other stays on the previous files. The process
then exits 1.

## What this program does not do

`build` does not harvest, and `harvest` does not run `enrich` or
`sigmac`. The program does not talk to a secret store. It does not
reload a daemon. It does not copy the directory onto another machine.
Those belong with the deployment that runs this command.

## Contributing

`docs/COMMIT.md` is the commit contract and `docs/BRANCHES.md` the
branch contract. `scripts/check-commit-msg.sh` is the check. See
`CONTRIBUTING.md`.

## Security

See `SECURITY.md`. Report privately. Do not open a public issue for a
bug that writes or publishes a secret.
