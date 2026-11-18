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
/var/lib/enrich/ua.json
/var/lib/enrich/tld.json
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
table is not a config this program accepts.

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
| `python` | yes | Interpreter. Absolute path, or a single token with no slash. |
| `module` | no | Default `sigmac`. A single token. |

The command is:

```
<python> -m <module> compile <rules> -o <tmp>/rules.sigmac --correlations <tmp>/rules.corr.json
```

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
   threat database that will be published. `sync` alone does not
   write the overlay. The timeout is `timeout_sync`.
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

## Commands

```
feedset render -c feedset.json
feedset build -c feedset.json
feedset build -c feedset.json --full
feedset build -c feedset.json --only enrich
feedset build -c feedset.json --only detect
```

`-c` is required. There is no default path.

## Example

`docs/examples/` is a fake kit. Threat input is the indicator
files: `indicators.csv`, `indicators.txt`, `indicators.json`,
`indicators.stix.json`, and `misp.misp.json`. They contain
documentation domains, URLs, addresses, one mailbox, and zero
hashes. The allow list, the user-agent table, the public-suffix
table, and the two rules use the same kind of invented value.
`docs/examples/README.md` lists each file. `make example` stages
that kit in a temporary directory and runs `render`, then
`build --only detect`. `render` writes the indicator paths into
`enrich.json`. The detect generation is what lands in `publish`.
This kit has no `threat.thrt`. `enrich build` is the program that
writes one, from those indicator files, and `make example` does
not run it. The `enrich` stand-in exits 1 and writes nothing, so
a full `build` against this kit publishes no database. Do not
point a collector at the temporary directory.
