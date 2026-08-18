Minimal zero-knowledge metadata sync service. The server stores opaque encrypted
record envelopes and encrypted key bundles

## Run

```sh
go run ./cmd/pawstash-sync
```

Environment variables:

- `PAWSTASH_SYNC_ADDR` — listen address, default `127.0.0.1:8787`;
- `PAWSTASH_SYNC_DB` — SQLite path, default `data/sync.db`.

## Container

```sh
docker build -t pawstash-sync .
docker run --rm -p 8787:8787 -v pawstash-sync-data:/data pawstash-sync
```
