-- Leases for uploads in progress. An upload registers a lease before writing
-- the S3 object and removes it in the same transaction that inserts the blob
-- row. GC never deletes an object or blob that has a live lease.
CREATE TABLE upload_leases (
    id         bigserial   PRIMARY KEY,
    hash       bytea       NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX upload_leases_hash_idx ON upload_leases (hash);
CREATE INDEX upload_leases_started_at_idx ON upload_leases (started_at);
