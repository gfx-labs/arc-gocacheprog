package server

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the server configuration. String values in the YAML file have
// ${ENV} references expanded before parsing.
type Config struct {
	Listen      string   `yaml:"listen"`
	DatabaseURL string   `yaml:"database_url"`
	S3          S3Config `yaml:"s3"`
	Auth        Auth     `yaml:"auth"`
	Storage     Storage  `yaml:"storage"`
	GC          GCConfig `yaml:"gc"`
}

type S3Config struct {
	Endpoint        string `yaml:"endpoint"`
	Region          string `yaml:"region"`
	Bucket          string `yaml:"bucket"`
	Prefix          string `yaml:"prefix"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	UsePathStyle    *bool  `yaml:"use_path_style"`
	CreateBucket    bool   `yaml:"create_bucket"`
}

type Storage struct {
	// InlineMaxBytes: blobs at or below this size are stored in postgres.
	InlineMaxBytes int64 `yaml:"inline_max_bytes"`
	// MaxBlobBytes rejects uploads larger than this.
	MaxBlobBytes int64 `yaml:"max_blob_bytes"`
	// TouchInterval: access timestamps are only rewritten when older than this.
	TouchInterval time.Duration `yaml:"touch_interval"`
	// TempDir spools large uploads while they are hashed. Empty uses os.TempDir.
	TempDir string `yaml:"temp_dir"`
	// MaxConcurrentUploads bounds parallel PUTs. Excess requests get 503.
	MaxConcurrentUploads int `yaml:"max_concurrent_uploads"`
	// RequestTimeout bounds reading a request and writing a response.
	RequestTimeout time.Duration `yaml:"request_timeout"`
}

type GCConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	// EntryTTL deletes entries not accessed for this long.
	EntryTTL time.Duration `yaml:"entry_ttl"`
	// BlobGrace keeps unreferenced blobs this long after last access, which
	// covers uploads that are between writing the blob and the entry.
	BlobGrace time.Duration `yaml:"blob_grace"`
	// NamespaceMaxBytes evicts least recently used entries per namespace
	// once the sum of entry sizes exceeds it. 0 disables.
	NamespaceMaxBytes int64 `yaml:"namespace_max_bytes"`
	// OrphanSweep lists the bucket and removes objects with no blob row.
	OrphanSweep bool `yaml:"orphan_sweep"`
	// UploadLease is how long an in-progress upload protects its object from
	// GC. Must exceed the longest upload. Expired leases are removed.
	UploadLease time.Duration `yaml:"upload_lease"`
}

type Auth struct {
	GHA    *GHAConfig  `yaml:"gha"`
	Static []StaticKey `yaml:"static"`
}

type GHAConfig struct {
	Issuer string `yaml:"issuer"`
	// JWKSURL overrides OIDC discovery of the signing keys.
	JWKSURL string `yaml:"jwks_url"`
	// Audience required on OIDC ID tokens.
	Audience string `yaml:"audience"`
	// AllowedOwners restricts which GitHub owners (orgs/users) may use the cache.
	AllowedOwners []string `yaml:"allowed_owners"`
	// AllowedRepositories restricts to "owner/name" entries. Checked in
	// addition to AllowedOwners when both are set.
	AllowedRepositories []string `yaml:"allowed_repositories"`
	// AllowAnyOwner must be set to accept tokens from any repository.
	AllowAnyOwner bool `yaml:"allow_any_owner"`
	// DefaultRefs are readable fallbacks for every ref, in order, like the
	// default branch in actions/cache.
	DefaultRefs []string `yaml:"default_refs"`
	// WriteEvents lists the event_name values whose tokens may write. Other
	// events get read-only access. Events like pull_request_target,
	// workflow_run and issue_comment run with the default branch as ref while
	// often building untrusted code, so they are excluded by default.
	WriteEvents []string `yaml:"write_events"`
	// AcceptRuntimeToken accepts ACTIONS_RUNTIME_TOKEN (scopes from the "ac" claim).
	AcceptRuntimeToken bool `yaml:"accept_runtime_token"`
	// RuntimeTokenIssuers is the set of issuers accepted for runtime tokens.
	// Empty means only Issuer. Runtime tokens are verified with the issuer's
	// JWKS unless RuntimeTokenJWKSURL is set.
	RuntimeTokenIssuers []string `yaml:"runtime_token_issuers"`
	RuntimeTokenJWKSURL string   `yaml:"runtime_token_jwks_url"`
}

type StaticKey struct {
	Name string `yaml:"name"`
	// Key is the plaintext token. Prefer KeySHA256 (hex sha256 of the token).
	Key        string   `yaml:"key"`
	KeySHA256  string   `yaml:"key_sha256"`
	Namespace  string   `yaml:"namespace"`
	WriteScope string   `yaml:"write_scope"`
	ReadScopes []string `yaml:"read_scopes"`
	ReadOnly   bool     `yaml:"read_only"`
}

func DefaultConfig() Config {
	return Config{
		Listen: ":8080",
		S3: S3Config{
			Region: "us-east-1",
			Prefix: "gocache/",
		},
		Storage: Storage{
			InlineMaxBytes: 32 << 10,
			MaxBlobBytes:         1 << 30,
			TouchInterval:        time.Hour,
			MaxConcurrentUploads: 32,
			RequestTimeout:       15 * time.Minute,
		},
		GC: GCConfig{
			Enabled:   true,
			Interval:  time.Hour,
			EntryTTL:  7 * 24 * time.Hour,
			BlobGrace:         6 * time.Hour,
			NamespaceMaxBytes: 20 << 30,
			OrphanSweep:       true,
			UploadLease:       time.Hour,
		},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	expanded := os.ExpandEnv(string(raw))
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("database_url is required")
	}
	if c.S3.Bucket == "" {
		return fmt.Errorf("s3.bucket is required")
	}
	if c.Auth.GHA == nil && len(c.Auth.Static) == 0 {
		return fmt.Errorf("at least one auth mode (auth.gha or auth.static) is required")
	}
	if g := c.Auth.GHA; g != nil {
		if g.Issuer == "" {
			g.Issuer = "https://token.actions.githubusercontent.com"
		}
		if g.Audience == "" {
			g.Audience = "arc-gocacheprog"
		}
		if g.WriteEvents == nil {
			g.WriteEvents = DefaultWriteEvents
		}
		if !g.AllowAnyOwner && len(g.AllowedOwners) == 0 && len(g.AllowedRepositories) == 0 {
			return fmt.Errorf("auth.gha needs allowed_owners, allowed_repositories, or allow_any_owner: true")
		}
	}
	for i, k := range c.Auth.Static {
		if k.Key == "" && k.KeySHA256 == "" {
			return fmt.Errorf("auth.static[%d]: key or key_sha256 is required", i)
		}
		if k.Namespace == "" {
			return fmt.Errorf("auth.static[%d]: namespace is required", i)
		}
		if !k.ReadOnly && k.WriteScope == "" {
			return fmt.Errorf("auth.static[%d]: write_scope is required unless read_only", i)
		}
	}
	if c.Storage.InlineMaxBytes < 0 {
		return fmt.Errorf("storage.inline_max_bytes must be >= 0")
	}
	if c.Storage.MaxConcurrentUploads <= 0 {
		return fmt.Errorf("storage.max_concurrent_uploads must be > 0")
	}
	if c.GC.UploadLease > 0 && c.GC.UploadLease < c.Storage.RequestTimeout {
		return fmt.Errorf("gc.upload_lease must be >= storage.request_timeout")
	}
	if c.GC.Enabled && c.GC.Interval <= 0 {
		return fmt.Errorf("gc.interval must be > 0")
	}
	return nil
}

// DefaultWriteEvents are the events that may write by default. In each of
// them the token's ref is the code being built.
var DefaultWriteEvents = []string{"push", "pull_request", "merge_group", "workflow_dispatch", "schedule"}
