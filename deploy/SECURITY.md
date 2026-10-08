# Deployment security checklist

This cache is part of the build trust boundary. A writer can map an action ID to arbitrary uploaded content within its write scope. SHA-256 and BLAKE3 verification check content integrity, not whether a compiler produced the content. Treat cache write credentials like build-system credentials.

## Required before deployment

- Terminate HTTPS at a trusted reverse proxy. Do not expose the server's plaintext HTTP listener directly to the Internet. Restrict the backend listener so clients cannot bypass the proxy.
- Clients require HTTPS for remote cache and OIDC token endpoints, except loopback development URLs. Credential-bearing redirects cannot change origin. Server OIDC discovery and signing-key endpoints also require HTTPS except loopback. Custom JWKS endpoints must respond directly, without redirects.
- Keep Postgres and the object store private. Use authenticated, encrypted connections across untrusted networks. For Postgres, use certificate verification such as `sslmode=verify-full` with a trusted CA. Do not copy the local Compose passwords or S3 credentials into production.
- Use a dedicated object-store bucket or prefix. Give its S3 identity only the required bucket listing and object read/write/delete permissions. Do not grant administrative privileges or make the bucket public.
- Restrict GitHub authentication to numeric owner IDs and, where practical, repository IDs. Names can be reused. Leave `allow_any_owner`, `accept_runtime_token`, and `allow_runtime_token_writes` disabled unless required and reviewed. `allow_any_owner` does not bypass `allowed_repositories`.
- Keep unsafe workflow events out of `write_events`. Do not execute untrusted code with a trusted branch's write scope or a static write key. An event allowlist cannot inspect what a workflow checks out or executes. Runtime tokens do not carry the OIDC event policy, so enabling their writes is a separate trust decision.
- Generate static keys with at least 32 random bytes. The published `dev-key` and Compose S3 credentials are development-only. SHA-256 key hashes do not make weak keys harder to guess. Prefer environment variables over the client's `-key` flag, which exposes the key in process arguments.
- Use ephemeral runners for untrusted pull requests. The local cache is partitioned by verified remote identity, server, and read/write scopes. This prevents accidental cache reuse, not hostile access by another process running as the same OS user. Never share writable cache directories between trusted and untrusted jobs. `ARC_GOCACHE_READONLY=1` disables remote uploads, not local writes.
- If initial identity verification fails, the client uses a private session cache rather than an existing identity cache. Normal exits and protocol errors remove that session. A killed process can leave its session directory behind. Clean abandoned directories only when no active job can be using them.
- Do not cache secrets or confidential artifacts that pull-request jobs must not read. Authorized PR jobs can read the configured default refs and base branch by design.
- Keep built-in admission limits enabled. They bound all HTTP requests before authentication and PUT/link operations and bytes per namespace. Add ingress limits for fleet-wide or volumetric attacks. Limits are per replica, and a restart grants a new burst. Rejected requests can also affect health probes, so review probe behavior under load.
- Allocate and monitor temporary disk, database storage, and object storage. Default upload settings permit up to 32 concurrent 1 GiB uploads per replica, with at most 8 per namespace. Reduce `storage.max_blob_bytes` and concurrency to fit actual capacity.
- Do not treat `gc.namespace_max_bytes` as an admission limit. It is an asynchronous logical cleanup policy, charging at least 1 KiB per entry. Blobs can accumulate between GC passes and remain for `gc.blob_grace` after entries are evicted. Admission limits bound ingestion rate, not total physical storage or database overhead.
- Keep `storage.request_timeout` positive and `gc.upload_lease` at least as long. Match proxy/backend timeouts. Monitor GC failures, lease buildup, rate-limit responses, and disk usage.
- Run the image as non-root with no added capabilities. Use a read-only root filesystem and size-limited writable temporary directory. Store production configuration and credentials outside the image.
- Rebuild and deploy both client and server after security changes. Previously downloaded binaries do not receive fixes automatically. Old unpartitioned local cache indexes are not imported by the hardened client.

## Release controls

- The Dockerfile, Compose dependencies, and third-party GitHub Actions are pinned to digests or commit SHAs. Deploy the newly built server image by digest and update pins through reviewed changes.
- Keep `govulncheck`, `go vet`, and race/integration tests in the release gate. Symbol reachability alone does not establish that an attacker controls the vulnerable input.
- Scan built images and their OS packages in the release environment. Go dependency scanning does not audit the base image, Postgres, or SeaweedFS.
- Back up Postgres and object storage according to availability requirements. A cache is disposable only when every dependent build can reconstruct its contents.
- Test from an external network that only the intended HTTPS service is reachable, disallowed tokens cannot read or write, and Postgres/S3 ports are not public.

## Compatibility changes

Unknown YAML keys and multiple YAML documents are rejected. Nonpositive request timeouts, invalid resource settings, and upload leases shorter than request timeouts are rejected. Runtime tokens are read-only unless `allow_runtime_token_writes: true` is explicitly set. Admission controls are enabled by default. Non-loopback plaintext credential endpoints are rejected. Signing-key refreshes have a 30-second cooldown, which can delay acceptance of a rotated key by that interval.

## Local Compose

`deploy/docker-compose.yaml` is a development stack with loopback-only published ports and fixed development credentials. The server drops capabilities, forbids privilege escalation, and uses a read-only root with a 1 GiB temporary filesystem. `deploy/config.compose.yaml` caps uploads at 16 MiB and 8 concurrent uploads, so maximum simultaneous body spooling is 128 MiB. Binding ports to loopback does not isolate untrusted local users or containers.
