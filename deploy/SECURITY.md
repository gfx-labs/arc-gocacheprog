# Deployment security checklist

This cache is part of the build trust boundary. A writer can map an action ID to arbitrary uploaded content within its write scope. SHA-256 and BLAKE3 verification check content integrity, not whether a compiler produced the content. Treat cache write credentials like build-system credentials.

## Required before deployment

- Terminate HTTPS at a trusted reverse proxy. Do not expose the server's plaintext HTTP listener directly to the Internet. Restrict the backend listener so clients cannot bypass the proxy.
- The client accepts plaintext HTTP only on loopback for development. Use HTTPS for remote cache and OIDC token endpoints. Authenticated redirects must not change the credential destination.
- Keep Postgres and the object store private. Use authenticated, encrypted connections across untrusted networks. For Postgres, use certificate verification such as `sslmode=verify-full` with a trusted CA. Do not copy the local Compose passwords or S3 credentials into production.
- Use a dedicated object-store bucket or prefix for this deployment. Give its S3 identity only the required bucket listing and object read/write/delete permissions. Do not grant administrative privileges or make the bucket public.
- Restrict GitHub authentication to your owner ID and, where practical, repository IDs. Names can be reused. Leave `allow_any_owner` and runtime-token support disabled unless explicitly required and reviewed.
- Keep unsafe workflow events out of `write_events`. Do not allow workflows that execute untrusted code while using a trusted branch's ref or static write key. An event allowlist cannot inspect what a workflow actually checks out or executes.
- Generate static keys with at least 32 random bytes. The published `dev-key` and the Compose S3 credentials are development-only. SHA-256 key hashes do not make weak keys harder to guess. Prefer environment variables over the client's `-key` flag, which exposes the key in process arguments.
- Use ephemeral runners for untrusted pull requests. Never share a writable `ARC_GOCACHE_DIR` between untrusted and trusted jobs, repositories, remote servers, or identities. The local action index is not partitioned by server identity, repository, or ref. `ARC_GOCACHE_READONLY=1` disables remote uploads, not local writes. A fresh directory for each job is a safe default.
- Do not cache secrets or confidential build artifacts that pull-request jobs must not read. Authorized PR jobs can read the configured default refs and their base branch by design.
- Put rate and concurrency limits at the reverse proxy, including unauthenticated requests and `/healthz`. Limit authenticated upload and link rates per trusted identity where possible. PUT slots alone do not bound authentication, downloads, or metadata writes.
- Allocate and monitor temporary disk space, database storage, and object storage. The default PUT settings permit up to 32 concurrent 1 GiB uploads per replica. Reduce `storage.max_blob_bytes` and `storage.max_concurrent_uploads` to fit the deployment.
- Do not treat `gc.namespace_max_bytes` as an admission limit. It is an asynchronous cleanup policy. Unique blobs can accumulate between GC passes and remain for `gc.blob_grace` after entries are evicted. Empty or tiny entries can consume database space without reaching the logical-byte quota.
- Keep `storage.request_timeout` positive and `gc.upload_lease` at least as long. Ensure your proxy and backend timeouts are compatible. Monitor GC failures and lease buildup.
- Run the image as non-root with no added capabilities. Use a read-only root filesystem and a size-limited writable temporary directory when supported. Store production configuration and credentials outside the image.
- Rebuild and deploy both the client and server after security changes. Previously downloaded binaries do not receive repository fixes automatically.

## Recommended release controls

- Pin deployed container images and third-party GitHub Actions to reviewed immutable digests or commit SHAs. Mutable version tags remain a supply-chain dependency.
- Keep `govulncheck`, `go vet`, and integration tests in the release gate. Review scanner findings for actual attacker-controlled inputs, not just symbol reachability.
- Scan the built container image and its OS packages in your release environment. Go dependency scanning does not audit the base image, Postgres, or SeaweedFS.
- Back up Postgres and the object store according to the availability requirements. A cache is disposable only when every dependent build can reconstruct its contents.
- Test from an external network that only the intended HTTPS service is reachable, that disallowed tokens cannot read or write, and that Postgres/S3 ports are not public.

## Local Compose

`deploy/docker-compose.yaml` is a development stack. Its published ports are intended to be loopback-only. Its fixed credentials are not production credentials. Binding a port to loopback is not a substitute for isolating untrusted local users or containers.
