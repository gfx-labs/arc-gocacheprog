package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gfx-labs/arc-gocacheprog/internal/client"
	"github.com/gfx-labs/arc-gocacheprog/internal/server"
)

// cacheSession drives one client process over the GOCACHEPROG protocol: it
// puts the given entries, then gets the given action IDs and closes.
type cacheSession struct {
	puts map[string][]byte
	gets []string
}

type getResult struct {
	Miss     bool
	DiskPath string
}

func runSession(t *testing.T, dir string, remote *client.Remote, s cacheSession) (map[string]getResult, *client.Prog) {
	t.Helper()
	p, err := client.New(client.Options{Dir: dir, Remote: remote, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	id := int64(1)
	for name, body := range s.puts {
		sum := sha256.Sum256(body)
		enc.Encode(client.Request{ID: id, Command: client.CmdPut, ActionID: action(name), OutputID: sum[:], BodySize: int64(len(body))}) //nolint:errcheck
		fmt.Fprintf(&in, "%q\n", base64.StdEncoding.EncodeToString(body))
		id++
	}
	byID := map[int64]string{}
	for _, name := range s.gets {
		enc.Encode(client.Request{ID: id, Command: client.CmdGet, ActionID: action(name)}) //nolint:errcheck
		byID[id] = name
		id++
	}
	enc.Encode(client.Request{ID: id, Command: client.CmdClose}) //nolint:errcheck

	var out bytes.Buffer
	if err := p.Run(context.Background(), &in, &out); err != nil {
		t.Fatal(err)
	}
	res := map[string]getResult{}
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r client.Response
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		if r.Err != "" {
			t.Fatalf("request %d: %s", r.ID, r.Err)
		}
		if name, ok := byID[r.ID]; ok {
			res[name] = getResult{Miss: r.Miss, DiskPath: r.DiskPath}
		}
	}
	return res, p
}

// One cache dir reused by jobs with different identities must not serve
// local hits across namespaces or scopes the server would not allow.
func TestLocalCacheIsolatedByIdentity(t *testing.T) {
	e := newEnv(t, func(c *server.Config) {
		c.Auth.Static = append(c.Auth.Static,
			server.StaticKey{Name: "main", Key: "key-main", Namespace: "repo-a", WriteScope: "refs/heads/main"},
			server.StaticKey{Name: "pr", Key: "key-pr", Namespace: "repo-a", WriteScope: "refs/pull/1/merge", ReadScopes: []string{"refs/heads/main"}},
			server.StaticKey{Name: "other", Key: "key-other", Namespace: "repo-b", WriteScope: "refs/heads/main"},
		)
	})
	dir := t.TempDir()
	main, pr, other := remote(e, "key-main"), remote(e, "key-pr"), remote(e, "key-other")

	run := func(r *client.Remote, s cacheSession) (map[string]getResult, *client.Prog) {
		return runSession(t, dir, r, s)
	}
	run(main, cacheSession{puts: map[string][]byte{"main-entry": []byte("trusted output")}})
	run(pr, cacheSession{puts: map[string][]byte{"pr-entry": []byte("untrusted output")}})

	// main must not see the PR entry, locally or remotely.
	got, p := run(main, cacheSession{gets: []string{"pr-entry", "main-entry"}})
	if !got["pr-entry"].Miss || p.Stats.LocalHits.Load() != 1 {
		t.Fatalf("main: pr-entry=%+v local_hits=%d", got["pr-entry"], p.Stats.LocalHits.Load())
	}
	// Another repository gets no local hits from repo-a.
	got, p = run(other, cacheSession{gets: []string{"main-entry", "pr-entry"}})
	if !got["main-entry"].Miss || !got["pr-entry"].Miss || p.Stats.LocalHits.Load() != 0 {
		t.Fatalf("other: %+v local_hits=%d", got, p.Stats.LocalHits.Load())
	}
	// A PR may read main through the server, which checks scopes.
	got, p = run(pr, cacheSession{gets: []string{"main-entry"}})
	if got["main-entry"].Miss || p.Stats.RemoteHits.Load() != 1 {
		t.Fatalf("pr: main-entry=%+v remote_hits=%d", got["main-entry"], p.Stats.RemoteHits.Load())
	}
	// Local-only mode uses its own partition.
	got, _ = run(nil, cacheSession{gets: []string{"main-entry", "pr-entry"}})
	if !got["main-entry"].Miss || !got["pr-entry"].Miss {
		t.Fatalf("local-only: %+v", got)
	}
}

// When the identity cannot be resolved, earlier local entries are not used
// and nothing written in that run is kept.
func TestLocalCacheUnknownIdentityUsesSession(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	runSession(t, dir, remote(e, testKey), cacheSession{puts: map[string][]byte{"entry": []byte("output")}})

	bad := remote(e, "wrong-key")
	got, _ := runSession(t, dir, bad, cacheSession{
		puts: map[string][]byte{"session-entry": []byte("x")},
		gets: []string{"entry", "session-entry"},
	})
	if !got["entry"].Miss || got["session-entry"].Miss {
		t.Fatalf("unknown identity: %+v", got)
	}
	if !strings.HasPrefix(got["session-entry"].DiskPath, filepath.Join(dir, "session")+string(filepath.Separator)) {
		t.Fatalf("session entry at %s, want under %s/session", got["session-entry"].DiskPath, dir)
	}
	if _, err := os.Stat(got["session-entry"].DiskPath); !os.IsNotExist(err) {
		t.Fatalf("session entry kept after close: %v", err)
	}
}
