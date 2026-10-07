// Command arc-gocacheprog is a GOCACHEPROG program backed by an
// arc-gocacheprog server.
//
//	GOCACHEPROG="arc-gocacheprog" go build ./...
//
// Configuration is read from the environment so it can be set once for a job:
//
//	ARC_GOCACHE_URL        server URL. Unset means local cache only.
//	ARC_GOCACHE_AUTH       "gha", "gha-runtime", "key", or "auto" (default).
//	                       auto uses gha when ACTIONS_ID_TOKEN_REQUEST_URL is
//	                       set, else key when ARC_GOCACHE_KEY is set.
//	ARC_GOCACHE_KEY        static key for "key" auth.
//	ARC_GOCACHE_AUDIENCE   OIDC audience for "gha" (default arc-gocacheprog).
//	ARC_GOCACHE_DIR        local cache dir (default <user cache dir>/arc-gocacheprog).
//	ARC_GOCACHE_READONLY   "1" disables uploads.
//	ARC_GOCACHE_VERBOSE    "1" logs stats and warnings, "2" logs debug.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gfx-labs/arc-gocacheprog/internal/client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "arc-gocacheprog:", err)
		os.Exit(1)
	}
}

func run() error {
	url := flag.String("url", os.Getenv("ARC_GOCACHE_URL"), "server URL")
	auth := flag.String("auth", envOr("ARC_GOCACHE_AUTH", "auto"), "auth mode: auto, gha, gha-runtime, key")
	key := flag.String("key", "", "static key (default $ARC_GOCACHE_KEY)")
	audience := flag.String("audience", envOr("ARC_GOCACHE_AUDIENCE", "arc-gocacheprog"), "OIDC audience for gha auth")
	dir := flag.String("dir", os.Getenv("ARC_GOCACHE_DIR"), "local cache dir")
	readOnly := flag.Bool("readonly", os.Getenv("ARC_GOCACHE_READONLY") == "1", "do not upload")
	verbose := flag.String("v", os.Getenv("ARC_GOCACHE_VERBOSE"), "verbosity: 1 info, 2 debug")
	whoami := flag.Bool("whoami", false, "print the identity the server assigns to this token and exit")
	flag.Parse()
	if *key == "" {
		*key = os.Getenv("ARC_GOCACHE_KEY")
	}

	level := slog.LevelWarn
	switch *verbose {
	case "1":
		level = slog.LevelInfo
	case "2":
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("component", "arc-gocacheprog")

	if *dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("no cache dir: set ARC_GOCACHE_DIR")
		}
		*dir = filepath.Join(base, "arc-gocacheprog")
	}

	var remote *client.Remote
	if *url != "" {
		tokens, err := tokenSource(*auth, *key, *audience)
		if err != nil {
			if *whoami {
				return err
			}
			// Never fail the build over cache auth; fall back to local only.
			log.Warn("remote cache disabled", "err", err)
		} else {
			remote = &client.Remote{
				BaseURL: *url,
				Tokens:  tokens,
				HTTP: &http.Client{Transport: &http.Transport{
					Proxy:               http.ProxyFromEnvironment,
					MaxIdleConnsPerHost: 64,
					IdleConnTimeout:     90 * time.Second,
					ForceAttemptHTTP2:   true,
				}},
			}
		}
	}

	if *whoami {
		if remote == nil {
			return fmt.Errorf("ARC_GOCACHE_URL is not set")
		}
		id, err := remote.Whoami(context.Background())
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(id)
	}

	p, err := client.New(client.Options{Dir: *dir, Remote: remote, ReadOnly: *readOnly, Log: log})
	if err != nil {
		return err
	}
	return p.Run(context.Background(), os.Stdin, os.Stdout)
}

func tokenSource(mode, key, audience string) (client.TokenSource, error) {
	if mode == "auto" {
		switch {
		case os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "":
			mode = "gha"
		case key != "":
			mode = "key"
		default:
			return nil, fmt.Errorf("no credentials: set ARC_GOCACHE_KEY or grant `id-token: write` in GitHub Actions")
		}
	}
	switch mode {
	case "gha":
		return client.NewGHATokenFromEnv(audience)
	case "gha-runtime":
		return client.RuntimeToken{}, nil
	case "key":
		if key == "" {
			return nil, fmt.Errorf("ARC_GOCACHE_KEY is empty")
		}
		return client.StaticToken(key), nil
	default:
		return nil, fmt.Errorf("unknown auth mode %q", mode)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
