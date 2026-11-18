# Example kit

Fake inputs for one `render` and one detect `build`. Nothing here
is a credential, a customer indicator, or a live feed. Addresses
are the documentation ranges in RFC 5737 (`203.0.113.50`,
`198.51.100.10`) and RFC 3849 (`2001:db8::50`). Names are the
RFC 2606 suffixes (`example`, `invalid`, `test`). The two
user-agent strings were invented for this tree. Hashes are the
right width, filled with zeroes.

The threat samples are indicator files. `enrich build` is what
compiles them into `threat.thrt`. This directory does not contain
a `threat.thrt`, an overlay database, or a MaxMind database.

| File | Role |
|---|---|
| `feedset.json` | Path illustration. Absolute paths under `/var/lib`. No secrets. The `indicators` list points at the five files below. |
| `enrich.json` | What `render` writes for that illustration. Each indicator is a `path` feed: `name`, `type`, `layer`, `path`. No `url`, no `key`. The key and the license are the fixed fake values below. |
| `indicators.csv` | CSV. Columns are type, value, confidence, category, feed, tlp. Rows: `ip`, `domain` (`example.invalid`, `feedset.example`), `url`, `email`, `md5`, `sha256`. |
| `indicators.txt` | One indicator per line. A `#` line is a comment. Domains, URLs, one mailbox, documentation addresses, one `md5`. |
| `indicators.json` | Dictionary. Indicator to `{tlp, feed, max_score, type}`. One domain, one URL, one address. |
| `indicators.stix.json` | STIX 2.1 bundle. Patterns: `domain-name:value`, `url:value`, `ipv4-addr:value`, `email-addr:value`. |
| `misp.misp.json` | Saved MISP body, type `misp`. Attributes include `domain`, `hostname`, `domain\|ip`, `url`, `email-src`, addresses, and the two zero hashes. `skip.example` has `to_ids` false, which `enrich` drops. `enrich sync` writes its own body at `misp.dest`. This file is the local sample, not that download. |
| `allow.json` | Overlay allow list. |
| `ua.json` | Hand-written user-agent table. `entries` is non-empty. `ExampleBot/1.0` is `suspicious`. `FeedsetSample/0.1` is `tool`. `harvest` does not emit `tool`. |
| `tld.json` | Hand-written public-suffix table. The rows are `example`, `invalid`, and `test`, all `common`. No `classifiers` array. |
| `rules/` | Two fake Sigma rules for `sigmac`. They are not detections, and `harvest` does not read this directory. |
| `sigma/` | Sample rules tree for `harvest.rules`. It is not an input of `make example`. Harvesting it keeps `ExampleBot/1.0` as an exact `malware` row (the title contains `malware`), writes `ExampleBot` to `contains`, `ExampleMine` to `prefixes`, and `ExampleEnd` to `suffixes`, drops the one-byte value, the wildcard, `bot`, `Chrome`, and `ExampleRegexToken`, and lists the classifier `encoded`. Suffixes `example` and `invalid` are `common` and `test` is `suspicious`, with `classifiers` `["uncommon"]`. That result is not `ua.json` or `tld.json`. |
| `standin/enrich` | Placeholder for `enrich`. It exits 1 and writes no file. |
| `standin/sigmac/` | Placeholder for `python -m sigmac`. It writes two non-empty compile files so the detect publish can be seen. |

The fixed fake secrets, used only by `make example`:

```
MISP_KEY=EXAMPLEMISPKEY0000000000000001
MAXMIND_ACCOUNT_ID=1000001
MAXMIND_LICENSE_KEY=EXAMPLELICENSE00__
```

`make example` copies this directory into a temporary tree, runs
`feedset render`, then `feedset build --only detect`, and prints
two directories. It does not run `harvest`. The staged
`feedset.json` has no `harvest` block and does not point at
`sigma/`. The `harvest` block in the checked-in `feedset.json` is
the field illustration: `rules` is `/var/lib/feeds/sigma-rules`
and `dest` is `/var/lib/feeds/catalog`. `indicators:` is the staged
work directory: the five indicator files, the rendered
`enrich.json`, and the copied allow list. `publish:` holds
`ua.json`, `tld.json`, `rules.sigmac`, and `rules.corr.json`. It
does not hold `threat.thrt`. Do not point a collector at either
directory.

Replace `enrich` and `sigma.python` in the config with the real
programs when you want `enrich build` to compile the indicator
files. Keep these samples as the inputs.
