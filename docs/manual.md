# feedset manual

`feedset` publishes eight files into one directory. Read
[the README](../README.md) for the two generations and the failure
rules. This file is the config and the command.

`enrich.json` is the file `enrich` reads. `feedset.json` is the file
`feedset` reads. Secrets are written only into `enrich.json`.

## Layout

```
/var/lib/feeds/feedset.json          mode 0644, no secrets
/var/lib/enrich/enrich.json          mode 0600, written by render
/var/lib/enrich/indicators.csv       indicator source, compiled by enrich build
/var/lib/enrich/threat.thrt          work copy, written by enrich build
/var/lib/enrich/allow.ovly           work copy
/var/lib/enrich/GeoLite2-City.mmdb
/var/lib/enrich/GeoLite2-ASN.mmdb
/var/lib/enrich/ua.json              work copy, from a path or from fetch
/var/lib/enrich/tld.json
/var/lib/feeds/catalog/ua.json       harvest output, beside tld.json and PIN
/var/lib/feeds/1/                    publish directory, the eight names
```

The paths are yours. The names inside the publish directory are not.
A relative path, a `..` component, or a symlink at a config path, a
work product, or a publish name is refused.

## feedset.json

Closed object. An unknown key is an error. A key named `key`,
`account_id`, `license_key`, `password`, `token`, `secret`,
`secret_id`, `role_id`, or `authorization` is an error at any depth.
The file must not be world-writable. `render` does not create the
files the paths point at. `build` does.

```json
{
  "enrich_config": "/var/lib/enrich/enrich.json",
  "publish": "/var/lib/feeds/1",
  "work": "/var/lib/enrich",
  "output": "/var/lib/enrich/threat.thrt",
  "enrich": "enrich",
  "min_thrt_bytes": 1048576,
  "lock": "/var/lib/enrich/feedset.lock",
  "misp": {
    "name": "misp",
    "url": "https://misp.example",
    "since": "7d",
    "dest": "/var/lib/enrich/misp.misp.json",
    "layer": "cti"
  },
  "geoip": {
    "dest_dir": "/var/lib/enrich",
    "editions": ["GeoLite2-City", "GeoLite2-ASN"]
  },
  "overlay": {
    "name": "overlay",
    "path": "/var/lib/enrich/allow.json",
    "dest": "/var/lib/enrich/allow.ovly"
  },
  "ua": {
    "name": "ua",
    "dest": "/var/lib/enrich/ua.json",
    "path": "/var/lib/feeds/catalog/ua.json"
  },
  "tld": {
    "name": "tld",
    "dest": "/var/lib/enrich/tld.json",
    "path": "/var/lib/feeds/catalog/tld.json"
  },
  "indicators": [
    {"name": "indicators", "type": "csv", "layer": "cti", "path": "/var/lib/enrich/indicators.csv"},
    {"name": "plaintext", "type": "txt", "layer": "cti", "path": "/var/lib/enrich/indicators.txt"},
    {"name": "dictionary", "type": "json", "layer": "cti", "path": "/var/lib/enrich/indicators.json"},
    {"name": "bundle", "type": "stix", "layer": "cti", "path": "/var/lib/enrich/indicators.stix.json"},
    {"name": "saved-misp", "type": "misp", "layer": "cti", "path": "/var/lib/enrich/sample.misp.json"}
  ],
  "sigma": {
    "rules": "/var/lib/feeds/rules",
    "python": "python3",
    "module": "sigmac"
  },
  "harvest": {
    "rules": "/var/lib/feeds/sigma-rules",
    "dest": "/var/lib/feeds/catalog"
  }
}
```

`docs/examples/feedset.json` is this object with `lock` omitted.

### Top level

| Field | Required | Meaning |
|---|---|---|
| `enrich_config` | yes | Where `render` writes `enrich.json`. Absolute. |
| `publish` | yes | Directory that receives the eight names. Absolute. |
| `work` | yes | Directory for the lock default and the fetch config. Absolute. |
| `output` | yes | `threat.thrt` work path. Absolute. Passed through as `enrich` `output`. |
| `enrich` | no | `enrich` executable. Default `enrich`. An absolute path, or a single token with no slash. |
| `min_thrt_bytes` | no | Floor for `threat.thrt`. Default 1048576. `0` disables the floor. A file under the floor is not published, and neither is the rest of the enrich generation. |
| `lock` | no | Lock file. Default `<work>/feedset.lock`. |
| `timeout_sync` | no | Seconds for `enrich sync`. Default 14400. |
| `timeout_fetch` | no | Seconds for `enrich fetch`. Default 600. |
| `timeout_sigma` | no | Seconds for `sigmac`. Default 600. |

`misp`, `geoip`, `overlay`, `ua`, `tld`, and `sigma` are required
objects. A feed set without the user-agent table or the public-suffix
table is not a config this program accepts. `harvest` is optional.
`render` and `build` ignore it.

### misp

| Field | Required | Meaning |
|---|---|---|
| `name` | no | Default `misp`. Lowercase letters, digits, hyphen. |
| `url` | yes | MISP server, `http` or `https`, no user, no path, no query. |
| `since` | yes | MISP `last` window. A positive integer and one unit: `m` minutes, `h` hours, `d` days. `7d` is seven days. There is no default. An omitted `since` would make `enrich` use `7d`, so `render` refuses it instead. |
| `dest` | yes | Where the `.misp.json` body is written. Absolute. |
| `layer` | no | `cti` or `cti_r`. Default `cti`. |

The MISP key comes from `MISP_KEY`. Length 16 to 128, ASCII letters
and digits. `render` writes it as the feed `key`.

### geoip

| Field | Required | Meaning |
|---|---|---|
| `dest_dir` | yes | Directory for `<edition>.mmdb`. Absolute. |
| `editions` | yes | Exactly `GeoLite2-City` then `GeoLite2-ASN`. |

`MAXMIND_ACCOUNT_ID` is 1 to 20 digits. `MAXMIND_LICENSE_KEY` is 16
to 128 characters, ASCII letters, digits, and `_`. Both are required.
`render` writes them as `account_id` and `license_key`.

`build` runs `enrich fetch` with those two editions. After fetch,
both `.mmdb` files must exist, must not be symlinks, and must be
non-empty. Otherwise the enrich generation is not published.

### overlay

| Field | Required | Meaning |
|---|---|---|
| `name` | no | Default `overlay`. |
| `path` | yes | Allow JSON. Absolute. `build` reads it before `enrich` runs. |
| `dest` | yes | `.ovly` work path. Absolute. |

`path` is a JSON object with a non-empty `entries` array. `build`
checks that before `enrich sync`. A bad allow file does not start
`enrich`.

### ua and tld

Same object shape. `name` defaults to `ua` or `tld`. `dest` is
required and absolute.

Exactly one source:

| Field | Meaning |
|---|---|
| `path` | Local JSON file. `feedset` checks it and copies it to `dest`. It is not a row in `enrich.json`. `enrich fetch` treats a `ua` or `tld` row without a URL as a hard error, so a local file must not be handed to `enrich`. |
| `url` | `https` URL, no userinfo. `render` writes a `ua` or `tld` feed with `url` and `dest`. `build` lets `enrich fetch` store the body, then checks that body. |

The checked document is UTF-8 JSON, at most 32 MiB, a JSON object,
with `entries` a non-empty array. `classifiers`, when present, is an
array. Any other shape is a detect failure: `sigmac` is not started,
and `ua.json`, `tld.json`, `rules.sigmac`, and `rules.corr.json` in
the publish directory stay as they were.

`feedset` does not interpret an entry. The enricher does the lookup.
The matcher uses the compiled rules that were written against those
tables.

### indicators

Optional. Omitted, or JSON `null`, is an empty list. Any other value
that is not a list is an error. Each element is an object. The only
keys are `name`, `type`, `layer`, and `path`.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Same alphabet as a feed name: lowercase letters, digits, hyphen. Unique inside the list. |
| `type` | yes | `csv`, `txt`, `ioc`, `json`, `lookup`, `misp`, or `stix`. |
| `layer` | no | `cti` or `cti_r`. Default `cti`. |
| `path` | yes | Absolute path of the indicator file. The suffix must match `type`. |

| `type` | Suffix |
|---|---|
| `csv` | `.csv` |
| `txt` | `.txt` |
| `ioc` | `.ioc` |
| `json` | `.json`, and not `.misp.json` or `.stix.json` |
| `lookup` | `.lookup` |
| `misp` | `.misp` or `.misp.json` |
| `stix` | `.stix` or `.stix.json` |

`render` writes one feed per element, after the overlay and before
any `ua` or `tld` URL row. The feed is `name`, `type`, `layer`, and
`path`. It has no `url` and no `key`. `feedset` does not open the
file. `enrich build` compiles it into `threat.thrt`. A missing file
or a row `enrich` refuses fails that build, and the enrich
generation is not published.

`enrich` owns the bytes inside the file. `docs/examples/` ships
five of these types: `indicators.csv`, `indicators.txt`,
`indicators.json`, `indicators.stix.json`, and `misp.misp.json`.
Addresses in those files are documentation ranges. Names are
RFC 2606.

### sigma

| Field | Required | Meaning |
|---|---|---|
| `rules` | yes | Directory of `.yml` or `.yaml` files. Absolute. At least one file, searched recursively. A symlink directory is refused. |
| `python` | one of | Interpreter. Absolute path, or a single token with no slash. |
| `module` | no | With `python` only. Default `sigmac`. A single token. |
| `sigmac` | one of | The `libsigma-sigmac` command. Absolute path, or a single token with no slash. |
| `fields` | no | With `sigmac` only. Absolute path of the produced field list. |
| `placeholders` | no | With `sigmac` only. Absolute path of the `\|expand` values. |

Exactly one of `python` and `sigmac` is set. With `python` the command
is:

```
<python> -m <module> compile <rules> -o <tmp>/rules.sigmac --correlations <tmp>/rules.corr.json
```

With `sigmac` the command is the following, and `--fields` and
`--placeholders` are passed only when they are set:

```
<sigmac> <rules> -o <tmp>/rules.sigmac --corr <tmp>/rules.corr.json [--fields <fields>] [--placeholders <placeholders>]
```

feedset does not read `fields` or `placeholders`. A missing file is a
compiler failure.

Both outputs must be non-empty regular files. They are published
with `ua.json` and `tld.json` after the compile. A failure before
that publish touches none of the four names.

## Secrets

| Variable | Check |
|---|---|
| `MISP_KEY` | 16 to 128 ASCII letters and digits |
| `MAXMIND_ACCOUNT_ID` | 1 to 20 digits |
| `MAXMIND_LICENSE_KEY` | 16 to 128 of `[A-Za-z0-9_]` |

`render` reads the environment once, before it opens the destination
for write. A missing or refused value exits and leaves `enrich.json`
unchanged. The process prints a fixed sentence. It does not print the
value.

`build` does not read these variables. It uses the `enrich.json` that
`render` wrote. Do not pass the values as arguments. The command line
is visible to other users.

## enrich.json

`render` replaces this file only after the checks pass. Mode `0600`.
The write is a temporary file in the same directory, then `rename`.

With a local user-agent table and a local public-suffix table, those
two feeds are absent here. Their bytes are published by `build` from
`path`.

```json
{
  "output": "/var/lib/enrich/threat.thrt",
  "geoip": {
    "account_id": "",
    "license_key": "",
    "dest_dir": "/var/lib/enrich",
    "editions": ["GeoLite2-City", "GeoLite2-ASN"]
  },
  "feeds": [
    {
      "name": "misp",
      "type": "misp",
      "layer": "cti",
      "url": "https://misp.example",
      "key": "",
      "since": "7d",
      "dest": "/var/lib/enrich/misp.misp.json"
    },
    {
      "name": "overlay",
      "type": "overlay",
      "path": "/var/lib/enrich/allow.json",
      "dest": "/var/lib/enrich/allow.ovly"
    },
    {
      "name": "indicators",
      "type": "csv",
      "layer": "cti",
      "path": "/var/lib/enrich/indicators.csv"
    }
  ]
}
```

`docs/examples/enrich.json` is the render of
`docs/examples/feedset.json`, including the five sample indicator
feeds. When `ua` or `tld` uses `url`, that feed is appended after
the indicator rows:

```json
{"name": "ua", "type": "ua", "url": "https://example.invalid/ua.json", "dest": "/var/lib/enrich/ua.json"}
```

```json
{"name": "tld", "type": "tld", "url": "https://example.invalid/tld.json", "dest": "/var/lib/enrich/tld.json"}
```

## build

One lock, `<work>/feedset.lock` unless `lock` is set. `flock`
exclusive, non-blocking, held for the whole command. A busy lock
exits 75 and prints `feedset is busy`.

Default, both generations:

1. Check the overlay allow file. A bad allow file does not start
   `enrich`. The detect generation still runs when its tables are
   local files.
2. `enrich -c enrich.json sync --apply`. `--full` inserts `--full`
   before `--apply`. `enrich` then uses `since` from the config
   instead of a cursor. Without `--full`, `enrich` uses the cursor
   and ignores `since`.
3. `enrich -c enrich.json build`. This writes the overlay and the
   threat database that will be published. `enrich sync --apply`
   also writes `threat.thrt` when the pull returns at least one
   attribute. On a first pull, or with `--full`, that write is a
   snapshot: the overlay is written before the database is folded.
   An incremental sync does not write the overlay. This `build`
   writes it. The timeout is `timeout_sync`.
4. `enrich fetch`, from a temporary mode `0600` config that contains
   `geoip` and any `ua` or `tld` row that has a URL. The temporary
   file is removed when `enrich` returns. On `--only detect` the
   temporary config has the URL rows and no `geoip`. On `--only
   enrich` it has `geoip` and no URL row. `fetch` still runs when
   `sync` or `build` failed, so a URL table can feed the detect
   generation.
5. Publish the enrich generation, or leave it, using the rules in
   the README. `sync` or `build` failing skips this publish.
6. Check a local `ua.path` and `tld.path`. Copy each one to `dest`
   only after it checks out. A URL table is the body `enrich fetch`
   just stored, and it is checked the same way. A bad table does
   not start `sigmac`.
7. Compile. Publish `ua.json`, `tld.json`, `rules.sigmac`, and
   `rules.corr.json`, or leave all four.

Publish mode is `0640`. Each name is staged in a private directory
under `publish` and then renamed into place. A check that fails
before the first rename does not change that generation. A crash
during the renames can leave a mix. The next successful generation
replaces the names it owns.

`build` prints one line per generation that published, and nothing
else:

```
enrich: threat.thrt threat.thrt_overlay GeoLite2-City.mmdb GeoLite2-ASN.mmdb
detect: ua.json tld.json rules.sigmac rules.corr.json
```

A generation that did not publish prints its reason on stderr. The
reason is a fixed sentence, or the last `enrich:` line that does not
contain `key` or `authorization`. Child stdout is discarded.

Exit 0 when every requested generation published. Exit 1 when one
did not. Exit 75 when the lock is busy. Exit 2 when the command line
is wrong.

## harvest

Optional. `render` and `build` do not read this block. `feedset
harvest` does. Set `rules` or `ref`, and set `dest`. Setting both
sources is an error. Omitting the block is an error only for the
`harvest` command.

| Field | Required | Meaning |
|---|---|---|
| `dest` | yes | Directory for `ua.json`, `tld.json`, and `PIN`. Absolute. |
| `rules` | one of | Sigma rules directory. Absolute. No download. A `..` path segment is refused. |
| `ref` | one of | `refs/heads/<name>`, `refs/tags/<name>`, or 40 hex digits. No `..` segment. The archive is `https://github.com/SigmaHQ/sigma/archive/<ref>.tar.gz`. |

When `build` copies local tables, set `ua.path` to `<dest>/ua.json`
and `tld.path` to `<dest>/tld.json`. A `url` on those objects is a
different source. `harvest` does not fill a URL.

The command holds `<work>/feedset.lock`, or `lock` when that field
is set. The same lock as `build`. A busy lock exits 75 and prints
`feedset is busy`. It does not download and it does not write.

### Tables

Both documents are UTF-8 JSON, mode `0644`, keys sorted, with a
trailing newline. `schema` is `1`. `product` is `feedset-ua` or
`feedset-tld`. `built_at` is UTC, `YYYY-MM-DDTHH:MM:SSZ`. `entries`
must be non-empty or the command refuses and leaves the previous
files. `classifiers` is an array. `build` uses the check in
`ua and tld` above. It does not interpret `class`, `product`, or
the classifier names.

```json
{
  "built_at": "2026-01-01T00:00:00Z",
  "classifiers": ["encoded"],
  "entries": [
    {
      "class": "malware",
      "id": "00000000-0000-4000-8000-000000000001",
      "label": "Example malware agent",
      "ua": "ExampleBot/1.0"
    }
  ],
  "product": "feedset-ua",
  "schema": 1
}
```

`tld.json` uses `tld` in each entry, `"product": "feedset-tld"`,
and `"classifiers": ["uncommon"]`. `id` is omitted when the rule
has none. The object above is the shape `harvest` writes. It is
not `docs/examples/ua.json`. That file is hand-written, and its
class `tool` is a value this command does not emit.

A user-agent row has `ua`, `class`, and `label`. The walk reads
`c-useragent`, `cs-user-agent`, `cs-useragent`,
`user_agent.original`, and `user-agent` from each selection that is
a map. A selection written as a list is skipped. A null value is
skipped. `class` is `malware` when the rule title or the file name
contains `malware`. Every other kept row is `suspicious`. `label`
is the rule title, or the file name without its suffix when the
title is missing. `id` is present when the rule has one.

An empty value with no modifier counts as the classifier `empty`
and is not a row. An `endswith` whose value is exactly `=` counts
as the classifier `encoded` and is not a row. Those two names are
listed only when at least one such value was seen, `empty` first.
They describe the table. They are not rows.

A value with no modifier, no `*` or `?`, and at least 3 bytes is an
exact row in `entries`. `contains`, `startswith`, and `endswith`
are written to `contains`, `prefixes`, and `suffixes` when the
value has no `*` or `?`, is at least 5 bytes, and does not occur
inside this reference User-Agent after ASCII lowercasing:

```
mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36
```

`mozilla` and `mozilla/` occur in that string, so they are not
prefixes. A scanner token such as a 6-byte name does not, so it is
kept. `|re`, `|base64`, `|wide`, and any chained modifier are
dropped. The same value, compared case-folded, is kept once inside
each list. `malware` wins. An exact row and a `contains` row may
name the same string. They are different comparisons. Each of the
three lists stops at 1024 rows.

`entries` is an exact compare of the whole User-Agent. `contains`
matches a User-Agent that includes the value. `prefixes` matches
the start. `suffixes` matches the end. Comparison is
case-insensitive. The higher class wins. An exact `malware` row is
reported on its own. A table hit wins over the trailing-`=`
classifier. The contains scan stops after 32768 automaton nodes.
The keys are omitted when the list is empty.

A suffix row has `tld`, `class`, and `label`. The walk reads only
two public rules: `b5de2919-b74a-4805-91a7-5049accbaefe` (`common`)
and `00d0b5ab-1f55-4120-8e83-487c0a7baf19` (`suspicious`). The
fields are `cs-host`, `c-host`, `dst_host`, `url.domain`, and
`destination.domain`, with no modifier or `|endswith`. The value is
lowercased, leading dots are removed, and only the last label is
kept. `.co.uk` becomes `uk`. `evil.example` becomes `example`. A
label is kept when it is 2 to 63 characters, ASCII letters or
digits, and not all digits. A `*` or `?` drops the value. `label`
is the rule title. `id` is the rule id. The same label is kept
once. `suspicious` wins.

`classifiers` on `tld.json` is always `["uncommon"]`. That name is
not a row. It records that a suffix absent from `entries` is the
uncommon class. This command does not do that lookup.

A YAML file that does not parse is skipped. A document with no
`detection` is skipped. When every file is skipped, or none of them
yields a row, the table is empty. An empty table does not replace
the previous files.

### Stamp

`PIN` is one line, mode `0644`. A `rules` source writes `sha256:`
and the digest of the YAML files in path order. Each file
contributes its relative path, a NUL, its bytes, and a NUL. A `ref`
source writes the SigmaHQ commit when the commit lookup returns 40
hex digits. When that lookup fails, `PIN` is the same kind of
digest of the YAML that was extracted. Both JSON files then carry
`sigmahq_ref`. They carry `sigmahq_commit` only when the commit is
known.

The archive download allows 15 seconds to connect, 300 seconds to
finish, and 128 MiB. The commit lookup allows 30 seconds and 1 MiB.
It uses the last path segment of `ref` (`master` for
`refs/heads/master`). A member over 2 MiB is refused. An archive
under 4096 bytes is refused. Only regular `.yml` and `.yaml`
members are extracted. A link or any other non-regular member is
skipped. A path that leaves the temporary directory refuses the
archive. Child output is discarded. The program builds that one
archive URL and the commit lookup.
`curl -L` may follow a redirect. No other URL is constructed. The
user agent is `feedset/0.1.0`.

`ua.json` is replaced, then `tld.json`, then `PIN`. A crash or a
refusal between those replacements can leave a mix. The next
successful harvest replaces all three. A refusal before the first
replacement leaves all three as they were. An empty table is that
kind of refusal. A symlink at `dest`, or at a file about to be
replaced, is refused. The second case can happen after `ua.json`
has already been replaced.

`feedset harvest -c feedset.json --check` prints nothing and writes
nothing. It holds the same lock. For `rules`, exit 0 when `PIN` is
the directory digest. For `ref`, it calls the commit lookup and
does not download the archive. Exit 0 when that lookup returns 40
hex digits and `PIN` is that commit. A `sha256:` stamp does not
pass `--check` on a `ref`, including a stamp written because an
earlier lookup failed. A missing `PIN` is exit 1 and the stderr line `harvest stamp
differs`. A failed lookup prints that same line. A missing
`harvest` block prints `harvest is missing` and does not take the
lock. Exit 75 when the lock is busy. Exit 2 when the command line
is wrong. A write that refuses the archive, or that finds an empty
table, is also exit 1, and it is not what `--check` does.

## Commands

```
feedset render -c feedset.json
feedset build -c feedset.json
feedset build -c feedset.json --full
feedset build -c feedset.json --only enrich
feedset build -c feedset.json --only detect
feedset harvest -c feedset.json
feedset harvest -c feedset.json --check
```

`-c` is required. There is no default path. `harvest` prints one
line when it writes:

```
harvest: ua.json tld.json
```

Exit 0 when the tables were written, or when `--check` matches.
For `rules`, a match is the directory digest. For `ref`, a match
is the commit that ref points to now. Exit 1 when the block is
missing, the stamp differs, the commit lookup fails, the archive
is refused, or a table is empty. Those cases share exit 1. The
stderr line distinguishes them. Exit 75 when the lock is busy.
Exit 2 when the command line is wrong.

## Example

`docs/examples/` is a fake kit. Threat input is the indicator
files: `indicators.csv`, `indicators.txt`, `indicators.json`,
`indicators.stix.json`, and `misp.misp.json`. They contain
documentation domains, URLs, addresses, one mailbox, and zero
hashes. The allow list, the user-agent table, the public-suffix
table, and the two rules use the same kind of invented value.
`docs/examples/README.md` lists each file. `make example` stages
that kit in a temporary directory and runs `render`, then
`build --only detect`. The staged config has no `harvest` block,
and `sigma/` is not an input of that run. The `harvest` object in
`docs/examples/feedset.json` is an illustration under `/var/lib`.
`render` writes the indicator paths into `enrich.json`. The detect
generation is what lands in `publish`.
This kit has no `threat.thrt`. `enrich build` is the program that
writes one, from those indicator files, and `make example` does
not run it. The `enrich` stand-in exits 1 and writes nothing, so
a full `build` against this kit publishes no database. Do not
point a collector at the temporary directory.
