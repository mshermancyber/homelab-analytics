# GeoIP and ASN enrichment

Enrichment answers the question every alert needs answered: *who owns the other
end of this connection?* An address with a Cloudflare ASN behaves very
differently from one on an unknown VPS, and most of the suppression logic leans
on that distinction.

Lookups run against **local MMDB files** — no external API calls, so there are
no rate limits, no per-alert latency, and nothing about your network leaves the
host.

## Install the databases

The free [DB-IP Lite](https://db-ip.com/db/lite.php) databases are the expected
source. Download the **City** and **ASN** editions in MMDB format and place
them here, with exactly these names:

```
backend/data/geoip/dbip-city-lite.mmdb    # country, city, region, lat/lon
backend/data/geoip/dbip-asn-lite.mmdb     # AS number, organisation name
```

```bash
mkdir -p backend/data/geoip
# download both MMDB files from https://db-ip.com/db/lite.php, then:
mv ~/Downloads/dbip-city-lite-*.mmdb backend/data/geoip/dbip-city-lite.mmdb
mv ~/Downloads/dbip-asn-lite-*.mmdb  backend/data/geoip/dbip-asn-lite.mmdb
```

Restart the backend. The log lines `DB-IP city database loaded` and
`DB-IP ASN database loaded` confirm they were picked up.

The databases are **not** shipped in this repository: they are ~135 MB together
and carry their own licence terms (DB-IP Lite is CC-BY 4.0 — attribution
required if you redistribute). Refresh them monthly; they are rebuilt on the
first of each month.

MaxMind's GeoLite2 City and ASN databases work too — rename them to the
filenames above.

## Running without them

Everything still runs. What you lose:

- country, city and ASN fields on alerts, and the dashboard's geo breakdown
- reputable-org suppression, which matches the GeoIP org name against
  `network.reputable_orgs`
- the org and ASN context in LLM triage prompts, which measurably degrades
  classification quality

Reverse DNS still works — it uses the host resolver, not the databases.

## Reverse DNS and the Tranco list

Enrichment also does a reverse-DNS lookup and checks the result against the
Tranco top 1M, which is how "this beacon is just a popular site re-resolving on
TTL expiry" gets suppressed. The Tranco list comes from the optional local feeds
database; see [FEEDS.md](FEEDS.md). Without it, domain-reputation checks are
skipped and a few more beaconing alerts get through.
