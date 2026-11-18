# feedset

Build the directory an enricher and a Sigma matcher read. The
manual is [docs/manual.md](docs/manual.md). Read it before changing
the command or the config.

The directory has eight names. They move in two generations. A
generation that fails leaves its previous files in place.

| File | Generation | What it is |
|---|---|---|
| `threat.thrt` | enrich | Threat database. `enrich sync --apply` pulls it, then `enrich build` writes it. |
| `threat.thrt_overlay` | enrich | Whitelist, tag, or add list (`.ovly`). |
| `GeoLite2-City.mmdb` | enrich | MaxMind City. |
| `GeoLite2-ASN.mmdb` | enrich | MaxMind ASN. |
| `ua.json` | detect | User-agent table. A JSON object with a non-empty `entries` array. |
| `tld.json` | detect | Public-suffix table. Same shape as `ua.json`. |
| `rules.sigmac` | detect | Compiled Sigma rules. |
| `rules.corr.json` | detect | Correlation file from the same compile. |

The user-agent table and the public-suffix table are part of the
detect generation, with the compiled rules. `feedset` does not
harvest them out of YAML. You give it the two JSON files, or a URL
for each. `sigmac` runs only after both tables have been checked. The
four detect files are replaced together.

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
runs `render`, then `build --only detect`. The threat inputs are
indicator files: a CSV, a plain-text list, a dictionary, a STIX
bundle, and a saved MISP body. The values are documentation
addresses (RFC 5737, RFC 3849), RFC 2606 names, one documentation
URL, one documentation mailbox, and hashes of the right width
filled with zeroes. `render` writes each file as a `path` feed in
`enrich.json`. Compiling those feeds into `threat.thrt` is
`enrich build`, and this run does not invoke it. The printed
`publish` directory holds the detect generation (`ua.json`,
`tld.json`, `rules.sigmac`, `rules.corr.json`). The two rule files
come from the `sigmac` stand-in. Do not point a collector at that
directory. `docs/examples/README.md` lists every sample.

## Commands

```
feedset render -c /var/lib/feeds/feedset.json
feedset build  -c /var/lib/feeds/feedset.json
feedset build  -c /var/lib/feeds/feedset.json --full
feedset build  -c /var/lib/feeds/feedset.json --only enrich
feedset build  -c /var/lib/feeds/feedset.json --only detect
```

`render` reads `feedset.json` and the three environment variables
below. It writes `enrich.json` mode `0600`. A refused secret does
not replace an existing `enrich.json`.

`build` publishes into the `publish` directory. `--full` is passed
to `enrich sync` and is ignored by the detect generation. `--only`
runs one generation.

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
- A second `build` that cannot take the lock exits 75. It does not
  start `enrich` or `sigmac`.

The enrich generation and the detect generation are independent. One
can publish while the other stays on the previous files. The process
then exits 1.

## What this program does not do

It does not harvest a rule tree into `ua.json` or `tld.json`. It does
not talk to a secret store. It does not reload a daemon. It does not
copy the directory onto another machine. Those belong with the
deployment that runs this command.

## Contributing

`docs/COMMIT.md` is the commit contract and `docs/BRANCHES.md` the
branch contract. `scripts/check-commit-msg.sh` is the check. See
`CONTRIBUTING.md`.

## Security

See `SECURITY.md`. Report privately. Do not open a public issue for a
bug that writes or publishes a secret.
