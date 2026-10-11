# Runtime data directory

Everything in here is generated at runtime and git-ignored:

| Path | Contents |
|---|---|
| `ueba.db` | SQLite database (events, alerts, baselines) |
| `geoip/` | DB-IP / GeoLite2 MMDB files you install — see `docs/GEOIP.md` |
| `model_cache/` | Persisted ML models (IsolationForest, autoencoder) |
| `feed_cache/` | Downloaded threat feeds and hot-reloaded IOC files |

Treat this directory as sensitive: the database records which hosts on your
network talked to which external addresses, and when. Keep it out of any backup
you share.
