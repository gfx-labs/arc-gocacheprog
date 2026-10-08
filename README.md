# arc-gocacheprog

A remote build cache for the Go toolchain. It has two binaries:

- `arc-gocacheprog` is a `GOCACHEPROG` program. The `go` command runs it as a subprocess and uses it to get and put build cache entries.
- `arc-gocacheprog-server` is an HTTP server that stores the entries. Metadata lives in Postgres. Blobs larger than 32 KiB go to S3 (SeaweedFS in production). Smaller blobs are stored inline in Postgres.

The client keeps a local on-disk cache and falls back to the server on a local miss. If the server is unreachable or auth fails, the build continues with the local cache only.

## How it works

```mermaid
flowchart LR
    go["go build"] -->|GOCACHEPROG protocol| client["arc-gocacheprog"]
    client --> local[("local cache dir")]
    client -->|"HTTPS, Bearer token"| server["arc-gocacheprog-server"]
    server --> pg[("Postgres: entries, small blobs, GC lock")]
    server --> s3[("S3 / SeaweedFS: blobs > 32 KiB")]
    gh["GitHub OIDC issuer"] -.->|"JWKS"| server
```

HTTP API:

| Method and path | Purpose |
| --- | --- |
| `GET /v1/actions/{actionID}` | Fetch an entry and its blob. 404 on miss. |
| `PUT /v1/actions/{actionID}` | Store an entry and blob. |
| `POST /v1/actions/{actionID}/link` | Store an entry for a blob that is already readable by the caller. No body. 404 means the blob must be uploaded with `PUT`. |
| `GET /v1/whoami` | Show the identity the server derived from the token. |
| `GET /healthz` | Liveness. |

Blobs are content addressed by BLAKE3-256. Object keys are `<prefix><h[0:2]>/<h[2:4]>/<hash>`. Identical blobs are stored once per server, and the client asks for a link before uploading a blob it has already pushed elsewhere.

## Security model

- **Namespaces.** For GitHub Actions tokens the namespace is the `repository_id` claim. Entries in one namespace are never visible from another.
- **Scopes.** Like `actions/cache`, every entry is written to a scope. The write scope is the ref in the token (for example `refs/heads/feature`). A job can read its own ref, the PR base ref, and the configured `default_refs`. A job can never write to a scope other than its own ref.
- **PR isolation.** A pull request job writes only to its own ref (`refs/pull/N/merge`), which other branches cannot read. It reads the base branch and the default refs.
- **Event allowlist.** Only workflow events listed in `gha.write_events` may write (default: `push`, `pull_request`, `merge_group`, `workflow_dispatch`, `schedule`). Tokens from other events can read but not write. `pull_request_target`, `workflow_run` and `issue_comment` run with the default branch as ref while often building untrusted code, so they are read only.
- **Owner allowlist.** `allowed_owner_ids` (preferred, names can be re-registered), `allowed_owners` and `allowed_repositories` restrict which repositories can use the server. A config that allows no one is rejected unless `allow_any_owner: true` is set. The repository allowlist still applies when any owner is allowed.
- **OutputID verification.** Go entries map an action ID to an output ID, which is the SHA-256 of the output file. The server hashes the uploaded body and rejects the upload if the SHA-256 does not match the claimed output ID. The client rechecks the SHA-256 of downloaded bodies before handing them to `go`.
- **BLAKE3 dedup.** The server computes the BLAKE3 hash of the uploaded body itself and does not trust the client's claim. Blobs are shared across namespaces on disk, but access goes through per-namespace references.
- **Link endpoint.** `POST .../link` succeeds only when the blob is already referenced by an entry in a scope the caller can read, and the size and SHA-256 match. A client cannot claim a blob it only knows the hash of, or one that belongs to another branch or repository.
- **Tokens.** OIDC ID tokens are verified against the issuer's JWKS, with the configured audience, RS256 only. Discovery and signing-key endpoints require HTTPS except loopback development URLs. Error responses do not include verification details. JWKS refreshes are limited to one upstream request per issuer every 30 seconds, with a 1 MiB response limit. Point custom `jwks_url` settings directly at the final endpoint, not a redirect. `ACTIONS_RUNTIME_TOKEN` is accepted only when `accept_runtime_token` is on. It is read-only unless `allow_runtime_token_writes` is explicitly enabled.
- **Admission controls.** The server limits concurrent uploads globally and per namespace. Enabled `limits` also bound all HTTP request rates and per-namespace write operations and uploaded bytes before spooling. Excess requests return 429 or 503. Rate limits are per replica and reset on restart.
- **Local cache.** Remote-mode entries are partitioned by the server URL and the namespace and scopes returned by authenticated `whoami`. Old unpartitioned entries are not reused. If identity verification fails, the client uses a private session directory rather than a previous build's cache. Local-only mode has a separate partition.

## GitHub Actions usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # lets the client request an OIDC token
    env:
      GOCACHEPROG: arc-gocacheprog
      ARC_GOCACHE_URL: https://gocache.example.com
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v7
        with:
          go-version-file: go.mod
          cache: false
      - name: Install arc-gocacheprog
        run: go install github.com/gfx-labs/arc-gocacheprog/cmd/arc-gocacheprog@latest
      - run: go build ./...
      - run: go test ./...
```

The client binary is also in the server image at `/usr/local/bin/arc-gocacheprog`, so it can be copied out of `ghcr.io/gfx-labs/arc-gocacheprog`.

Client environment variables:

| Variable | Meaning |
| --- | --- |
| `ARC_GOCACHE_URL` | Server URL. Unset means local cache only. |
| `ARC_GOCACHE_AUTH` | `gha`, `gha-runtime`, `key` or `auto` (default). `auto` uses `gha` when `ACTIONS_ID_TOKEN_REQUEST_URL` is set, otherwise `key` if `ARC_GOCACHE_KEY` is set. |
| `ARC_GOCACHE_KEY` | Static key for `key` auth. |
| `ARC_GOCACHE_AUDIENCE` | OIDC audience (default `arc-gocacheprog`). Must match `gha.audience` on the server. |
| `ARC_GOCACHE_DIR` | Local cache dir (default `<user cache dir>/arc-gocacheprog`). |
| `ARC_GOCACHE_READONLY` | `1` disables uploads. |
| `ARC_GOCACHE_VERBOSE` | `1` logs a stats line and warnings, `2` logs debug. |

`arc-gocacheprog -whoami` prints the identity the server assigns to the current token. Remote cache and OIDC token endpoints must use HTTPS, except loopback HTTP for local development. Authenticated redirects cannot change the original origin.

Use ephemeral runners for untrusted CI jobs. Local identity partitioning prevents accidental cross-repository or cross-scope reuse, but it cannot protect files from malicious jobs running as the same OS user. `ARC_GOCACHE_READONLY` only disables remote uploads. The initial identity request has a 30-second timeout. A failed identity request uses a fresh session cache that is removed on orderly exit.

## Local usage with a static key

Start the local stack (Postgres, SeaweedFS and the server, using `deploy/config.compose.yaml`):

```sh
docker compose -f deploy/docker-compose.yaml up --build
```

Then build with the key `dev-key`:

```sh
go install ./cmd/arc-gocacheprog
GOCACHEPROG=arc-gocacheprog \
ARC_GOCACHE_URL=http://127.0.0.1:8080 \
ARC_GOCACHE_KEY=dev-key \
ARC_GOCACHE_VERBOSE=1 \
go build ./...
```

The stats line on exit shows `local_hits`, `remote_hits`, `misses`, `uploads` and `linked`. Set `SERVER_PORT` or `SEAWEEDFS_S3_PORT` to change the host ports. The compose credentials are fixed and for local use only.

## Server configuration

Run the server with a YAML file:

```sh
arc-gocacheprog-server -config config.yaml
```

`ARC_GOCACHE_CONFIG` sets the default path. `${VAR}` references in the file are expanded from the environment. Unknown YAML fields and unsafe resource limits are rejected. [deploy/config.example.yaml](deploy/config.example.yaml) lists every option with comments. Schema migrations run at startup.

Read `deploy/SECURITY.md` before production deployment. The server needs a trusted HTTPS proxy, private database and object storage, and storage monitoring. In-process admission limits apply per replica, not across the fleet. Namespace quotas are asynchronous GC policies, not hard storage admission limits.

Container image: `ghcr.io/gfx-labs/arc-gocacheprog`. The default command reads `/etc/arc-gocacheprog/config.yaml`. The image runs as a non-root user on distroless.

## Observability

**Logs.** JSON on stderr. Every request gets a `request_id`, also returned in the `X-Request-Id` header. Rejected (4xx) and failed (5xx) requests are logged at warn and error with the route, auth kind, namespace, write scope, status, duration and internal cause. Successful requests and cache misses log at info with `access_log: true`, otherwise at debug. When tracing is on, lines carry `trace_id` and `span_id`.

**Traces and metrics.** OpenTelemetry, configured with the standard `OTEL_*` environment variables. Nothing is exported unless one is set:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318   # traces and metrics over OTLP/HTTP
OTEL_EXPORTER_OTLP_PROTOCOL=grpc                          # optional, with port 4317
OTEL_METRICS_EXPORTER=prometheus                          # optional, serves /metrics on port 9464
OTEL_EXPORTER_PROMETHEUS_HOST=0.0.0.0                     # the default is localhost, unreachable by a scraper
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=prod
```

Each request has a server span named by route, with child spans for Postgres queries (otelpgx), S3 calls (otelaws) and upload spooling. Incoming trace context from clients is linked, not used as the parent. GC passes are their own traces.

Metrics, besides the standard `http.server.*`, `db.client.*`, `pgxpool.*` and Go runtime metrics:

| Metric | Attributes | Meaning |
| --- | --- | --- |
| `gocache.lookups` | `result`: hit, miss, error | Entry lookups. Hit rate is hit / (hit + miss). |
| `gocache.uploads` | `result`: stored, deduplicated, error | Uploads that reached storage. |
| `gocache.links` | `result`: linked, missing, error | Link requests that reached storage. |
| `gocache.rejections` | `reason`: auth, bad_request, no_scope, request_rate, write_rate, upload_slots, hash_mismatch | Requests rejected before storage. |
| `gocache.upload.size`, `gocache.download.size` | | Bytes received and served. |
| `gocache.uploads.active` | | Uploads holding a concurrency slot. |
| `gocache.gc.runs` | `result`: done, skipped, error | GC passes. |
| `gocache.gc.removed` | `kind`: expired, evicted, blob, orphan | Items removed by GC. |
| `gocache.gc.removed.size`, `gocache.gc.duration` | | Bytes removed and pass duration. |

Metrics carry no namespace or repository labels, to keep cardinality bounded. Use logs or traces for per-repository detail.

## Garbage collection

The server runs GC every `gc.interval` while `gc.enabled` is set. A Postgres lock keeps multiple replicas from running it at once. Each pass does the following:

- Deletes entries whose `accessed_at` is older than `gc.entry_ttl`. Access times are only rewritten when older than `storage.touch_interval`, so the TTL is loose by up to that interval.
- If `gc.namespace_max_bytes` is set, evicts the least recently used entries in each namespace that is over quota. Each entry counts at least 1024 bytes so empty and tiny entries cannot bypass quota accounting.
- Deletes blobs with no references once they have been unreferenced for `gc.blob_grace`. The grace period covers uploads that wrote the blob but have not yet written the entry.
- If `gc.orphan_sweep` is set, lists the bucket and deletes objects that have no blob row.

Run one pass and exit, for example from a CronJob:

```sh
arc-gocacheprog-server -config config.yaml -gc-once
```

## Tests

```sh
go vet ./...
go test ./...
```

The integration tests start Postgres with `embedded-postgres`, which downloads Postgres binaries on first run, and use `grafana/s3-mock` for S3.

## Layout

- `cmd/arc-gocacheprog`: GOCACHEPROG client.
- `cmd/arc-gocacheprog-server`: HTTP server.
- `internal/api`: HTTP contract shared by both.
- `internal/client`, `internal/server`: implementations.
- `integration`: end to end tests.
- `deploy`: example config and local compose stack.
