package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Identity is the authorization context derived from a token.
type Identity struct {
	Kind      string
	Subject   string
	Namespace string
	// WriteScope is empty when the identity may not write.
	WriteScope string
	// ReadScopes are searched in order on reads. WriteScope is always first when set.
	ReadScopes []string
}

func (i *Identity) CanRead(scope string) bool { return slices.Contains(i.ReadScopes, scope) }

type authError struct {
	status int
	msg    string
	// cause and attrs are logged but not sent to the client.
	cause error
	attrs []any
}

func (e *authError) Error() string { return e.msg }

// because records the underlying reason and log attributes.
func (e *authError) because(cause error, attrs ...any) *authError {
	e.cause = cause
	e.attrs = attrs
	return e
}

func unauthorized(format string, a ...any) *authError {
	return &authError{status: http.StatusUnauthorized, msg: fmt.Sprintf(format, a...)}
}

func forbidden(format string, a ...any) *authError {
	return &authError{status: http.StatusForbidden, msg: fmt.Sprintf(format, a...)}
}

// Authenticator turns a bearer token into an Identity.
type Authenticator struct {
	static []staticEntry
	gha    *ghaAuth
}

type staticEntry struct {
	digest [32]byte
	key    StaticKey
}

func NewAuthenticator(cfg Auth) (*Authenticator, error) {
	a := &Authenticator{}
	for i, k := range cfg.Static {
		var e staticEntry
		e.key = k
		switch {
		case k.KeySHA256 != "":
			b, err := hex.DecodeString(k.KeySHA256)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("auth.static[%d].key_sha256 must be 64 hex chars", i)
			}
			copy(e.digest[:], b)
		default:
			e.digest = sha256.Sum256([]byte(k.Key))
		}
		a.static = append(a.static, e)
	}
	if cfg.GHA != nil {
		g := *cfg.GHA
		if g.Issuer == "" {
			g.Issuer = "https://token.actions.githubusercontent.com"
		}
		if err := validateGHAURLs(g); err != nil {
			return nil, err
		}
		a.gha = newGHAAuth(g)
	}
	return a, nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return "", false
	}
	return strings.TrimSpace(tok), true
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	// JWTs have exactly two dots. Static keys must not look like one.
	if strings.Count(token, ".") == 2 {
		if a.gha == nil {
			return nil, unauthorized("gha auth is not enabled")
		}
		return a.gha.authenticate(ctx, token)
	}
	if len(a.static) == 0 {
		return nil, unauthorized("static key auth is not enabled")
	}
	d := sha256.Sum256([]byte(token))
	var match *StaticKey
	for i := range a.static {
		// Constant time per entry, and no early exit.
		if subtle.ConstantTimeCompare(d[:], a.static[i].digest[:]) == 1 && match == nil {
			match = &a.static[i].key
		}
	}
	if match == nil {
		return nil, unauthorized("invalid key")
	}
	id := &Identity{
		Kind:      "static",
		Subject:   match.Name,
		Namespace: "key:" + match.Namespace,
	}
	if !match.ReadOnly {
		id.WriteScope = match.WriteScope
		id.ReadScopes = append(id.ReadScopes, match.WriteScope)
	}
	for _, s := range match.ReadScopes {
		if !slices.Contains(id.ReadScopes, s) {
			id.ReadScopes = append(id.ReadScopes, s)
		}
	}
	return id, nil
}

// ghaAuth verifies GitHub Actions tokens.
//
// Two token types are accepted:
//
//   - OIDC ID tokens (ACTIONS_ID_TOKEN_REQUEST_URL, needs "id-token: write").
//     The audience must match. Scopes are derived from the ref claims the same
//     way actions/cache does: a run writes to its own ref and reads from its own
//     ref, the PR base branch, and the configured default refs.
//   - Runtime tokens (ACTIONS_RUNTIME_TOKEN), opt in. Scopes come from the "ac"
//     claim that GitHub computes for actions/cache.
type ghaAuth struct {
	cfg GHAConfig

	mu   sync.Mutex
	sets map[string]*keySetEntry // by issuer
}

type keySetEntry struct {
	mu       sync.Mutex
	keys     oidc.KeySet
	lastErr  error
	failedAt time.Time
}

const (
	discoveryTimeout = 10 * time.Second
	discoveryBackoff = 30 * time.Second
)

func newGHAAuth(cfg GHAConfig) *ghaAuth {
	return &ghaAuth{cfg: cfg, sets: map[string]*keySetEntry{}}
}

// jwksURL returns the configured JWKS override for issuer, if any.
func (g *ghaAuth) jwksURL(issuer string) string {
	if issuer == g.cfg.Issuer {
		return g.cfg.JWKSURL
	}
	return g.cfg.RuntimeTokenJWKSURL
}

// keySet returns the JWKS for issuer. The JWKS URL comes from OIDC discovery
// (custom enterprise issuers serve JWKS at a different path) unless an
// override is configured. Discovery is bounded by a timeout and failures are
// cached briefly so a GitHub outage does not stall every request.
func (g *ghaAuth) keySet(ctx context.Context, issuer string) (oidc.KeySet, error) {
	g.mu.Lock()
	e, ok := g.sets[issuer]
	if !ok {
		e = &keySetEntry{}
		g.sets[issuer] = e
	}
	g.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.keys != nil {
		return e.keys, nil
	}
	if e.lastErr != nil && time.Since(e.failedAt) < discoveryBackoff {
		return nil, e.lastErr
	}
	url := g.jwksURL(issuer)
	if url == "" {
		if !strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://") {
			return nil, fmt.Errorf("issuer %q is not a URL; set a jwks url for it", issuer)
		}
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
		defer cancel()
		p, err := oidc.NewProvider(oidc.ClientContext(dctx, httpClient), issuer)
		if err == nil {
			var meta struct {
				JWKSURI string `json:"jwks_uri"`
			}
			if cerr := p.Claims(&meta); cerr != nil || meta.JWKSURI == "" {
				err = fmt.Errorf("no jwks_uri")
			}
			url = meta.JWKSURI
		}
		if err != nil {
			e.lastErr = fmt.Errorf("oidc discovery for %s: %w", issuer, err)
			e.failedAt = time.Now()
			return nil, e.lastErr
		}
	}
	// Discovered JWKS URLs must be HTTPS (or loopback) like configured ones.
	if err := validateAuthURL(url); err != nil {
		e.lastErr = fmt.Errorf("jwks url for %s: %w", issuer, err)
		e.failedAt = time.Now()
		return nil, e.lastErr
	}
	// The key set refreshes on unknown kids. The JWKS client rate limits
	// upstream fetches so forged kids cannot hammer the issuer.
	e.keys = oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), newJWKSClient()), url)
	e.lastErr = nil
	return e.keys, nil
}

// httpClient bounds JWKS and discovery requests.
var httpClient = &http.Client{
	Timeout:       discoveryTimeout,
	CheckRedirect: authRedirect,
	Transport:     limitBodyTransport{base: http.DefaultTransport, max: maxDiscoveryBytes},
}

func (g *ghaAuth) verify(ctx context.Context, raw, issuer string, audience bool) (*ghaClaims, error) {
	ks, err := g.keySet(ctx, issuer)
	if err != nil {
		return nil, &authError{status: http.StatusServiceUnavailable, msg: "token verification unavailable", cause: err}
	}
	v := oidc.NewVerifier(issuer, ks, &oidc.Config{
		ClientID:             g.cfg.Audience,
		SkipClientIDCheck:    !audience,
		SupportedSigningAlgs: []string{oidc.RS256},
	})
	tok, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, unauthorized("invalid token").because(err)
	}
	var c ghaClaims
	if err := tok.Claims(&c); err != nil {
		return nil, unauthorized("invalid token").because(fmt.Errorf("claims: %w", err))
	}
	return &c, nil
}

type ghaClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Ref               string `json:"ref"`
	RefType           string `json:"ref_type"`
	BaseRef           string `json:"base_ref"`
	EventName         string `json:"event_name"`
	// Runtime token only.
	AC string `json:"ac"`
}

type acScope struct {
	Scope      string
	Permission int
}

func (g *ghaAuth) authenticate(ctx context.Context, raw string) (*Identity, error) {
	unverified, err := parseUnverified(raw)
	if err != nil {
		return nil, unauthorized("invalid token").because(fmt.Errorf("parse jwt: %w", err))
	}
	if unverified.AC != "" {
		return g.authenticateRuntime(ctx, raw, unverified.Issuer)
	}
	c, err := g.verify(ctx, raw, g.cfg.Issuer, true)
	if err != nil {
		var ae *authError
		if errors.As(err, &ae) && ae.status < 500 {
			// Unverified, but tells an operator which job sent the bad token.
			ae.attrs = append(ae.attrs, "unverified_repository", unverified.Repository)
		}
		return nil, err
	}
	if c.RepositoryID == "" || c.Repository == "" || c.Ref == "" {
		return nil, unauthorized("token is missing repository_id, repository or ref")
	}
	if err := g.checkRepo(c); err != nil {
		return nil, err
	}
	id := &Identity{
		Kind:       "gha",
		Subject:    c.Subject,
		Namespace:  "gh:" + c.RepositoryID,
		ReadScopes: []string{c.Ref},
	}
	// Only events where ref is the code being built may write. Others, like
	// pull_request_target, run under the default branch ref and would let
	// untrusted code write into it.
	if slices.Contains(g.cfg.WriteEvents, c.EventName) {
		id.WriteScope = c.Ref
	}
	add := func(s string) {
		if s != "" && !slices.Contains(id.ReadScopes, s) {
			id.ReadScopes = append(id.ReadScopes, s)
		}
	}
	if c.BaseRef != "" {
		add(qualifyBranch(c.BaseRef))
	}
	for _, r := range g.cfg.DefaultRefs {
		add(qualifyBranch(r))
	}
	return id, nil
}

func (g *ghaAuth) authenticateRuntime(ctx context.Context, raw, issuer string) (*Identity, error) {
	if !g.cfg.AcceptRuntimeToken {
		return nil, unauthorized("runtime tokens are not accepted")
	}
	issuers := g.cfg.RuntimeTokenIssuers
	if len(issuers) == 0 {
		issuers = []string{g.cfg.Issuer}
	}
	if !slices.Contains(issuers, issuer) {
		return nil, unauthorized("invalid token").because(errors.New("untrusted runtime token issuer"), "iss", issuer)
	}
	// Runtime tokens are signed with the same keys but carry a different
	// issuer and an audience we do not control.
	c, err := g.verify(ctx, raw, issuer, false)
	if err != nil {
		return nil, err
	}
	if c.RepositoryID == "" {
		return nil, unauthorized("runtime token has no repository_id")
	}
	if err := g.checkRepo(c); err != nil {
		return nil, err
	}
	var scopes []acScope
	if err := json.Unmarshal([]byte(c.AC), &scopes); err != nil {
		return nil, unauthorized("invalid token").because(fmt.Errorf("ac claim: %w", err))
	}
	id := &Identity{Kind: "gha-runtime", Subject: c.Subject, Namespace: "gh:" + c.RepositoryID}
	// Highest permission first, matching how the actions cache service orders lookups.
	slices.SortStableFunc(scopes, func(a, b acScope) int { return b.Permission - a.Permission })
	for _, s := range scopes {
		if s.Scope == "" {
			continue
		}
		// Write grants are ignored unless enabled, since some GitHub setups
		// grant untrusted triggers write access to the default branch scope.
		if s.Permission&2 != 0 && id.WriteScope == "" && g.cfg.AllowRuntimeTokenWrites {
			id.WriteScope = s.Scope
		}
		if s.Permission&1 != 0 && !slices.Contains(id.ReadScopes, s.Scope) {
			id.ReadScopes = append(id.ReadScopes, s.Scope)
		}
	}
	if len(id.ReadScopes) == 0 && id.WriteScope == "" {
		return nil, unauthorized("token grants no cache scopes")
	}
	return id, nil
}

// checkRepo enforces the allowlists. Numeric IDs are preferred since names
// can be reused after an account or repository is deleted. Runtime tokens may
// not carry names, so repository IDs are accepted in allowed_repositories.
// AllowAnyOwner only lifts the owner check, allowed_repositories still applies.
func (g *ghaAuth) checkRepo(c *ghaClaims) error {
	owner := c.RepositoryOwner
	if owner == "" && c.Repository != "" {
		owner, _, _ = strings.Cut(c.Repository, "/")
	}
	ownerSet := len(g.cfg.AllowedOwners) > 0 || len(g.cfg.AllowedOwnerIDs) > 0
	ownerOK := !ownerSet || g.cfg.AllowAnyOwner
	for _, o := range g.cfg.AllowedOwners {
		if owner != "" && strings.EqualFold(o, owner) {
			ownerOK = true
		}
	}
	for _, id := range g.cfg.AllowedOwnerIDs {
		if c.RepositoryOwnerID != "" && id == c.RepositoryOwnerID {
			ownerOK = true
		}
	}
	repoOK := len(g.cfg.AllowedRepositories) == 0
	for _, r := range g.cfg.AllowedRepositories {
		if (c.Repository != "" && strings.EqualFold(r, c.Repository)) || r == c.RepositoryID {
			repoOK = true
		}
	}
	if !ownerOK || !repoOK {
		return forbidden("repository is not allowed").because(nil,
			"repository", c.Repository, "repository_id", c.RepositoryID, "owner_id", c.RepositoryOwnerID)
	}
	return nil
}

func qualifyBranch(ref string) string {
	if strings.HasPrefix(ref, "refs/") {
		return ref
	}
	return "refs/heads/" + ref
}

// parseUnverified decodes JWT claims without checking the signature. Only
// used to pick the verification path.
func parseUnverified(raw string) (*ghaClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 jwt segments")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, err
	}
	var c ghaClaims
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
