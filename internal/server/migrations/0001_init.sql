-- +goose Up
-- Content-addressed blobs keyed by BLAKE3-256. Small blobs are stored inline,
-- larger ones in S3 under a sharded key derived from the hash.
CREATE TABLE blobs (
    hash        bytea       PRIMARY KEY CHECK (length(hash) = 32),
    -- sha256 of the content, which is what cmd/go uses as the OutputID
    sha256      bytea       NOT NULL CHECK (length(sha256) = 32),
    size        bigint      NOT NULL CHECK (size >= 0),
    inline_data bytea,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- loose: only bumped when older than the server's touch interval
    accessed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX blobs_accessed_at_idx ON blobs (accessed_at);

-- One Go cache action entry. namespace isolates tenants (a GitHub repository,
-- a static key group), scope isolates refs within a namespace.
CREATE TABLE entries (
    namespace   text        NOT NULL,
    scope       text        NOT NULL,
    action_id   bytea       NOT NULL,
    output_id   bytea       NOT NULL,
    blob_hash   bytea       NOT NULL REFERENCES blobs (hash),
    size        bigint      NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    accessed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, scope, action_id)
);

CREATE INDEX entries_blob_hash_idx ON entries (blob_hash);
CREATE INDEX entries_accessed_at_idx ON entries (accessed_at);
CREATE INDEX entries_ns_blob_idx ON entries (namespace, blob_hash);

-- +goose Down
DROP TABLE entries;
DROP TABLE blobs;
