package server

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRejectsUnsafeSettings(t *testing.T) {
	base := `database_url: postgres://localhost/cache
s3:
  bucket: cache
auth:
  static:
    - key: test-key
      namespace: test
      write_scope: main
`
	cases := []struct {
		name, extra, want string
	}{
		{"misspelled read-only policy", "      readonly: true\n", "readonly"},
		{"unknown upload limit", "storage:\n  max_blob_byte: 1\n", "max_blob_byte"},
		{"unbounded request lifetime", "storage:\n  request_timeout: 0s\n", "storage.request_timeout"},
		{"zero tenant upload limit", "storage:\n  max_concurrent_uploads_per_namespace: 0\n", "storage.max_concurrent_uploads_per_namespace"},
		{"negative tenant upload limit", "storage:\n  max_concurrent_uploads_per_namespace: -1\n", "storage.max_concurrent_uploads_per_namespace"},
		{"negative request lifetime", "storage:\n  request_timeout: -1s\n", "storage.request_timeout"},
		{"zero blob limit", "storage:\n  max_blob_bytes: 0\n", "storage.max_blob_bytes"},
		{"overflowing blob limit", "storage:\n  max_blob_bytes: 9223372036854775807\n", "storage.max_blob_bytes"},
		{"inline above blob limit", "storage:\n  max_blob_bytes: 1\n", "storage.inline_max_bytes"},
		{"disabled upload lease expiry", "gc:\n  upload_lease: 0s\n", "gc.upload_lease"},
		{"negative blob grace", "gc:\n  blob_grace: -1s\n", "gc.blob_grace"},
		{"negative namespace quota", "gc:\n  namespace_max_bytes: -1\n", "gc.namespace_max_bytes"},
		{"negative entry ttl", "gc:\n  entry_ttl: -1s\n", "gc.entry_ttl"},
		{"negative touch interval", "storage:\n  touch_interval: -1s\n", "storage.touch_interval"},
		{"unbounded request burst", "limits:\n  request_burst: 0\n", "request_burst"},
		{"invalid request rate", "limits:\n  requests_per_sec: .nan\n", "requests_per_sec"},
		{"unbounded write burst", "limits:\n  write_burst: 0\n", "write_burst"},
		{"invalid write rate", "limits:\n  writes_per_sec: .inf\n", "writes_per_sec"},
		{"unlimited package rate", "limits:\n  writes_per_sec: 1.7976931348623157e308\n", "writes_per_sec"},
		{"upload above byte burst", "limits:\n  write_bytes_burst: 1024\n", "write_bytes_burst"},
		{"unbounded tenant map", "limits:\n  max_tenants: 0\n", "max_tenants"},
		{"plaintext OIDC discovery", "  gha:\n    allowed_owners: [gfx-labs]\n    issuer: http://issuer.example.com\n", "auth.gha.issuer"},
		{"plaintext signing keys", "  gha:\n    allowed_owners: [gfx-labs]\n    jwks_url: http://keys.example.com/jwks\n", "auth.gha.jwks_url"},
		{"plaintext runtime signing keys", "  gha:\n    allowed_owners: [gfx-labs]\n    runtime_token_jwks_url: http://keys.example.com/jwks\n", "auth.gha.runtime_token_jwks_url"},
		{"runtime writes without runtime auth", "  gha:\n    allowed_owners: [gfx-labs]\n    allow_runtime_token_writes: true\n", "allow_runtime_token_writes"},
		{"multiple YAML documents", "---\nlisten: ':9090'\n", "document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(base+tc.extra), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestConfigResourceBoundaries(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits = LimitsConfig{}
	cfg.DatabaseURL = "postgres://localhost/cache"
	cfg.S3.Bucket = "cache"
	cfg.Auth.Static = []StaticKey{{Key: "test-key", Namespace: "test", WriteScope: "main"}}
	cfg.Storage.InlineMaxBytes = 0
	cfg.Storage.MaxBlobBytes = math.MaxInt64 - 1
	cfg.Storage.RequestTimeout = time.Second
	cfg.GC.UploadLease = time.Second
	cfg.GC.EntryTTL = 0
	cfg.GC.NamespaceMaxBytes = 0
	cfg.GC.BlobGrace = 0
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
