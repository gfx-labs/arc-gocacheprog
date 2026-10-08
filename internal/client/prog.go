package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeebo/blake3"

	"github.com/gfx-labs/arc-gocacheprog/internal/api"
)

// Options configures a Prog.
type Options struct {
	// Dir is the local disk cache directory. Entries live in a partition of
	// it chosen from the remote identity, see selectRoot.
	Dir string
	// Remote is nil for a local-only cache.
	Remote *Remote
	// RemoteUnavailable marks a configured remote that could not be set up,
	// for example missing credentials. The local cache then uses a temporary
	// partition instead of the shared local-only one.
	RemoteUnavailable bool
	// ReadOnly disables uploads.
	ReadOnly bool
	// UploadConcurrency is the number of parallel uploads.
	UploadConcurrency int
	// GetTimeout bounds a single remote get.
	GetTimeout time.Duration
	// CloseTimeout bounds how long close waits for pending uploads.
	CloseTimeout time.Duration
	// MaxErrors disables the remote after this many consecutive failures.
	MaxErrors int
	// IdentityTimeout bounds the whoami call that selects the local partition.
	IdentityTimeout time.Duration
	Log             *slog.Logger
}

// Stats are reported on close.
type Stats struct {
	Gets, LocalHits, RemoteHits, Misses atomic.Int64
	Puts, Uploads, Linked, UploadErrs   atomic.Int64
	RemoteGetErrs                       atomic.Int64
	BytesDown, BytesUp                  atomic.Int64
}

// Prog implements the GOCACHEPROG protocol on top of a local disk cache and
// an optional remote server.
type Prog struct {
	opts  Options
	log   *slog.Logger
	Stats Stats

	// root is the local partition in use. session is set when it is a
	// temporary directory removed at shutdown.
	root    string
	session bool

	outMu sync.Mutex
	out   *bufio.Writer

	uploads  chan upload
	uploadWG sync.WaitGroup
	inflight sync.WaitGroup
	stopOnce sync.Once

	remoteDisabled atomic.Bool
	consecErrs     atomic.Int64
	readDisabled   atomic.Bool
	writeDisabled  atomic.Bool
}

type upload struct {
	actionID, outputID, blake3 []byte
	size                       int64
	path                       string
}

func New(opts Options) (*Prog, error) {
	if opts.Dir == "" {
		return nil, errors.New("cache dir is required")
	}
	if opts.UploadConcurrency <= 0 {
		opts.UploadConcurrency = 8
	}
	if opts.GetTimeout <= 0 {
		opts.GetTimeout = 2 * time.Minute
	}
	if opts.CloseTimeout <= 0 {
		opts.CloseTimeout = 5 * time.Minute
	}
	if opts.MaxErrors <= 0 {
		opts.MaxErrors = 20
	}
	if opts.IdentityTimeout <= 0 {
		opts.IdentityTimeout = 30 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	p := &Prog{opts: opts, log: opts.Log}
	if err := p.selectRoot(); err != nil {
		return nil, err
	}
	for _, d := range []string{"o", "a", "tmp"} {
		if err := os.MkdirAll(filepath.Join(p.root, d), 0o700); err != nil {
			p.removeSession()
			return nil, err
		}
	}
	if opts.Remote != nil && !opts.ReadOnly {
		p.uploads = make(chan upload, 4096)
		for range opts.UploadConcurrency {
			p.uploadWG.Add(1)
			go p.uploader()
		}
	}
	return p, nil
}

// selectRoot picks the local partition. Entries are only reused by a later
// process that the same server identifies with the same namespace and scopes,
// so a job cannot get local hits for entries another identity wrote.
//
//	<Dir>/local/          local-only mode (no remote configured)
//	<Dir>/remote/<hash>/  sha256 of server URL and verified identity
//	<Dir>/session/<rand>/ identity unknown; removed when Run returns
//
// Entries at the top of Dir from older versions are never read. Session
// dirs left by killed processes are not removed automatically, since another
// live process may own them.
//
// With a remote configured, startup waits for one whoami call, bounded by
// IdentityTimeout (30s default) when the server is unreachable.
func (p *Prog) selectRoot() error {
	dir := p.opts.Dir
	if p.opts.Remote == nil && !p.opts.RemoteUnavailable {
		p.root = filepath.Join(dir, "local")
		return nil
	}
	err := errors.New("remote cache is not configured correctly")
	if p.opts.Remote != nil {
		ctx, cancel := context.WithTimeout(context.Background(), p.opts.IdentityTimeout)
		defer cancel()
		var id *api.Identity
		if id, err = p.opts.Remote.Whoami(ctx); err == nil {
			var key string
			if key, err = partitionKey(p.opts.Remote.BaseURL, id); err == nil {
				p.root = filepath.Join(dir, "remote", key)
				return nil
			}
		}
	}
	p.log.Warn("could not resolve cache identity, local cache entries from earlier builds are not used", "err", err)
	sessions := filepath.Join(dir, "session")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		return err
	}
	root, err := os.MkdirTemp(sessions, "s-")
	if err != nil {
		return err
	}
	p.root, p.session = root, true
	return nil
}

// partitionKey hashes the canonical server URL and the identity the server
// verified. Tokens are not included because OIDC tokens rotate per job.
func partitionKey(baseURL string, id *api.Identity) (string, error) {
	u, err := CheckCredentialURL(baseURL, false)
	if err != nil {
		return "", err
	}
	if id == nil || id.Namespace == "" {
		return "", errors.New("server returned an identity without a namespace")
	}
	reads := id.ReadScopes
	if reads == nil {
		reads = []string{}
	}
	b, err := json.Marshal(struct {
		V          int      `json:"v"`
		URL        string   `json:"url"`
		Kind       string   `json:"kind"`
		Namespace  string   `json:"namespace"`
		WriteScope string   `json:"write_scope"`
		ReadScopes []string `json:"read_scopes"`
	}{1, u.Scheme + "://" + strings.ToLower(u.Host) + strings.TrimRight(u.EscapedPath(), "/"),
		id.Kind, id.Namespace, id.WriteScope, reads})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// removeSession deletes this process's temporary partition, if any.
func (p *Prog) removeSession() {
	if p.session {
		os.RemoveAll(p.root) //nolint:errcheck
		p.session = false
	}
}

func (p *Prog) remoteOK() bool { return p.opts.Remote != nil && !p.remoteDisabled.Load() }

// noteRemote tracks consecutive failures and disables the remote past the
// limit so a dead server does not slow every action down.
func (p *Prog) noteRemote(err error) {
	if err == nil {
		p.consecErrs.Store(0)
		return
	}
	if IsAuthError(err) {
		return
	}
	if n := p.consecErrs.Add(1); n >= int64(p.opts.MaxErrors) && p.remoteDisabled.CompareAndSwap(false, true) {
		p.log.Warn("disabling remote cache after repeated errors", "errors", n, "last", err)
	}
}

// Run serves the protocol until close, EOF or a protocol error. Every return
// waits for in-flight gets, drains queued uploads (bounded by CloseTimeout)
// and removes a session partition.
func (p *Prog) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	defer p.shutdown()
	p.out = bufio.NewWriter(out)
	if err := p.send(&Response{ID: 0, KnownCommands: []Cmd{CmdGet, CmdPut, CmdClose}}); err != nil {
		return err
	}
	r := newReader(in)
	for {
		req, err := r.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch req.Command {
		case CmdGet:
			p.inflight.Add(1)
			go func() {
				defer p.inflight.Done()
				p.send(p.handleGet(ctx, req)) //nolint:errcheck
			}()
		case CmdPut:
			// The body must be consumed from stdin before the next request.
			res := p.handlePut(req, r)
			if res == nil {
				return fmt.Errorf("protocol error reading put body for request %d", req.ID)
			}
			p.send(res) //nolint:errcheck
		case CmdClose:
			// Uploads finish before the close response, so cmd/go does not
			// exit while they are pending.
			p.shutdown()
			return p.send(&Response{ID: req.ID})
		default:
			p.send(&Response{ID: req.ID, Err: "unknown command " + string(req.Command)}) //nolint:errcheck
		}
	}
}

func (p *Prog) send(res *Response) error {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	b, err := jsonMarshal(res)
	if err != nil {
		return err
	}
	if _, err := p.out.Write(b); err != nil {
		return err
	}
	if err := p.out.WriteByte('\n'); err != nil {
		return err
	}
	return p.out.Flush()
}

// shutdown runs once per Prog.
func (p *Prog) shutdown() { p.stopOnce.Do(p.stop) }

func (p *Prog) stop() {
	p.inflight.Wait()
	if p.uploads != nil {
		close(p.uploads)
		done := make(chan struct{})
		go func() { p.uploadWG.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(p.opts.CloseTimeout):
			p.log.Warn("timed out waiting for uploads")
		}
		p.uploads = nil
	}
	// After a CloseTimeout, uploaders may still read files here. Removing
	// them makes those uploads fail; the server never stores unverified bodies.
	p.removeSession()
	s := &p.Stats
	if p.opts.Remote != nil {
		p.log.Info("cache stats",
			"gets", s.Gets.Load(), "local_hits", s.LocalHits.Load(), "remote_hits", s.RemoteHits.Load(),
			"misses", s.Misses.Load(), "puts", s.Puts.Load(), "uploads", s.Uploads.Load(),
			"linked", s.Linked.Load(), "upload_errors", s.UploadErrs.Load(), "get_errors", s.RemoteGetErrs.Load(),
			"bytes_down", s.BytesDown.Load(), "bytes_up", s.BytesUp.Load())
	}
}

// Local layout:
//
//	o/<xx>/<outputID hex>   body files handed to cmd/go
//	a/<xx>/<actionID hex>   "v1 <outputID hex> <size> <unixnano>\n"
func (p *Prog) outputPath(outputID []byte) string {
	h := hex.EncodeToString(outputID)
	return filepath.Join(p.root, "o", h[:2], h)
}

func (p *Prog) actionPath(actionID []byte) string {
	h := hex.EncodeToString(actionID)
	return filepath.Join(p.root, "a", h[:2], h)
}

type localEntry struct {
	outputID []byte
	size     int64
	time     time.Time
}

func (p *Prog) readLocal(actionID []byte) *localEntry {
	b, err := os.ReadFile(p.actionPath(actionID))
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) != 4 || f[0] != "v1" {
		return nil
	}
	out, err := hex.DecodeString(f[1])
	if err != nil || len(out) != sha256.Size {
		return nil
	}
	size, err1 := strconv.ParseInt(f[2], 10, 64)
	ns, err2 := strconv.ParseInt(f[3], 10, 64)
	if err1 != nil || err2 != nil || size < 0 {
		return nil
	}
	fi, err := os.Stat(p.outputPath(out))
	if err != nil || fi.Size() != size {
		return nil
	}
	return &localEntry{outputID: out, size: size, time: time.Unix(0, ns)}
}

func (p *Prog) writeLocal(actionID, outputID []byte, size int64, t time.Time) error {
	path := p.actionPath(actionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := fmt.Sprintf("v1 %x %d %d\n", outputID, size, t.UnixNano())
	return writeAtomic(p.root, path, []byte(data))
}

func writeAtomic(dir, path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Join(dir, "tmp"), "idx-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}

// installOutput moves a verified temp file to its content-addressed path.
func (p *Prog) installOutput(tmp string, outputID []byte) (string, error) {
	dst := p.outputPath(outputID)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return dst, nil
}

func (p *Prog) handleGet(ctx context.Context, req *Request) *Response {
	p.Stats.Gets.Add(1)
	if len(req.ActionID) == 0 || len(req.ActionID) > api.MaxIDLen {
		return &Response{ID: req.ID, Err: "invalid action id"}
	}
	if e := p.readLocal(req.ActionID); e != nil {
		p.Stats.LocalHits.Add(1)
		t := e.time
		return &Response{ID: req.ID, OutputID: e.outputID, Size: e.size, Time: &t, DiskPath: p.outputPath(e.outputID)}
	}
	if !p.remoteOK() || p.readDisabled.Load() {
		p.Stats.Misses.Add(1)
		return &Response{ID: req.ID, Miss: true}
	}
	res, err := p.remoteGet(ctx, req)
	p.noteRemote(err)
	if err != nil {
		p.Stats.RemoteGetErrs.Add(1)
		if IsAuthError(err) && p.readDisabled.CompareAndSwap(false, true) {
			p.log.Warn("remote cache reads rejected, continuing without them", "err", err)
		} else {
			p.log.Debug("remote get failed", "action", hex.EncodeToString(req.ActionID), "err", err)
		}
		p.Stats.Misses.Add(1)
		return &Response{ID: req.ID, Miss: true}
	}
	if res.Miss {
		p.Stats.Misses.Add(1)
	} else {
		p.Stats.RemoteHits.Add(1)
	}
	return res
}

func (p *Prog) remoteGet(ctx context.Context, req *Request) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, p.opts.GetTimeout)
	defer cancel()
	f, err := os.CreateTemp(filepath.Join(p.root, "tmp"), "get-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	sh := sha256.New()
	e, err := p.opts.Remote.Get(ctx, req.ActionID, io.MultiWriter(f, sh))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if e == nil {
		return &Response{ID: req.ID, Miss: true}, nil
	}
	// OutputID is the sha256 of the body; never hand cmd/go unverified bytes.
	if got := sh.Sum(nil); !bytes.Equal(got, e.OutputID) {
		return nil, fmt.Errorf("remote body sha256 %x does not match output id %x", got, e.OutputID)
	}
	path, err := p.installOutput(tmp, e.OutputID)
	if err != nil {
		return nil, err
	}
	t := e.Time
	if t.IsZero() {
		t = time.Now()
	}
	if err := p.writeLocal(req.ActionID, e.OutputID, e.Size, t); err != nil {
		p.log.Debug("write local index", "err", err)
	}
	p.Stats.BytesDown.Add(e.Size)
	return &Response{ID: req.ID, OutputID: e.OutputID, Size: e.Size, Time: &t, DiskPath: path}, nil
}

// handlePut stores the body locally, answers immediately and queues the
// upload. It returns nil only when the protocol stream is broken.
func (p *Prog) handlePut(req *Request, r *reader) *Response {
	p.Stats.Puts.Add(1)
	f, err := os.CreateTemp(filepath.Join(p.root, "tmp"), "put-*")
	if err != nil {
		if req.BodySize > 0 {
			if _, err := r.body(io.Discard); err != nil {
				return nil
			}
		}
		return &Response{ID: req.ID, Err: err.Error()}
	}
	tmp := f.Name()
	sh := sha256.New()
	bh := blake3.New()
	var n int64
	if req.BodySize > 0 {
		n, err = r.body(io.MultiWriter(f, sh, bh))
		if err != nil {
			f.Close()
			os.Remove(tmp)
			return nil
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return &Response{ID: req.ID, Err: err.Error()}
	}
	if n != req.BodySize {
		os.Remove(tmp)
		return &Response{ID: req.ID, Err: fmt.Sprintf("body size %d does not match BodySize %d", n, req.BodySize)}
	}
	sum := sh.Sum(nil)
	if len(req.ActionID) == 0 || len(req.ActionID) > api.MaxIDLen {
		os.Remove(tmp)
		return &Response{ID: req.ID, Err: "invalid action id"}
	}
	if !bytes.Equal(sum, req.OutputID) {
		os.Remove(tmp)
		return &Response{ID: req.ID, Err: "body sha256 does not match OutputID"}
	}
	path, err := p.installOutput(tmp, req.OutputID)
	if err != nil {
		os.Remove(tmp)
		return &Response{ID: req.ID, Err: err.Error()}
	}
	if err := p.writeLocal(req.ActionID, req.OutputID, n, time.Now()); err != nil {
		p.log.Debug("write local index", "err", err)
	}
	if p.uploads != nil && p.remoteOK() && !p.writeDisabled.Load() {
		u := upload{actionID: req.ActionID, outputID: req.OutputID, blake3: bh.Sum(nil), size: n, path: path}
		select {
		case p.uploads <- u:
		default:
			p.log.Debug("upload queue full, skipping", "action", hex.EncodeToString(req.ActionID))
		}
	}
	return &Response{ID: req.ID, DiskPath: path}
}

func (p *Prog) uploader() {
	defer p.uploadWG.Done()
	for u := range p.uploads {
		if !p.remoteOK() || p.writeDisabled.Load() {
			continue
		}
		err := p.doUpload(u)
		p.noteRemote(err)
		if err != nil {
			p.Stats.UploadErrs.Add(1)
			if IsAuthError(err) && p.writeDisabled.CompareAndSwap(false, true) {
				p.log.Warn("remote cache writes rejected, continuing without them", "err", err)
			} else {
				p.log.Debug("upload failed", "action", hex.EncodeToString(u.actionID), "err", err)
			}
		}
	}
}

func (p *Prog) doUpload(u upload) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	linked, err := p.opts.Remote.Link(ctx, u.actionID, u.outputID, u.blake3, u.size)
	if err != nil {
		return err
	}
	if linked {
		p.Stats.Linked.Add(1)
		return nil
	}
	var perr error
	for attempt := range 4 {
		perr = p.opts.Remote.Put(ctx, u.actionID, u.outputID, u.blake3, u.size, u.path)
		if statusOf(perr) != http.StatusServiceUnavailable {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	if perr != nil {
		return perr
	}
	p.Stats.Uploads.Add(1)
	p.Stats.BytesUp.Add(u.size)
	return nil
}
