package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeebo/blake3"
)

// Options configures a Prog.
type Options struct {
	// Dir is the local disk cache directory. Files returned to cmd/go live here.
	Dir string
	// Remote is nil for a local-only cache.
	Remote *Remote
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
	Log       *slog.Logger
}

// Stats are reported on close.
type Stats struct {
	Gets, LocalHits, RemoteHits, Misses atomic.Int64
	Puts, Uploads, Linked, UploadErrs  atomic.Int64
	RemoteGetErrs                      atomic.Int64
	BytesDown, BytesUp                 atomic.Int64
}

// Prog implements the GOCACHEPROG protocol on top of a local disk cache and
// an optional remote server.
type Prog struct {
	opts  Options
	log   *slog.Logger
	Stats Stats

	outMu sync.Mutex
	out   *bufio.Writer

	uploads  chan upload
	uploadWG sync.WaitGroup
	inflight sync.WaitGroup

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
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	for _, d := range []string{"o", "a", "tmp"} {
		if err := os.MkdirAll(filepath.Join(opts.Dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	p := &Prog{opts: opts, log: opts.Log}
	if opts.Remote != nil && !opts.ReadOnly {
		p.uploads = make(chan upload, 4096)
		for range opts.UploadConcurrency {
			p.uploadWG.Add(1)
			go p.uploader()
		}
	}
	return p, nil
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

// Run serves the protocol until close or EOF.
func (p *Prog) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	p.out = bufio.NewWriter(out)
	if err := p.send(&Response{ID: 0, KnownCommands: []Cmd{CmdGet, CmdPut, CmdClose}}); err != nil {
		return err
	}
	r := newReader(in)
	for {
		req, err := r.next()
		if errors.Is(err, io.EOF) {
			p.shutdown()
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
			p.inflight.Wait()
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

func (p *Prog) shutdown() {
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
	return filepath.Join(p.opts.Dir, "o", h[:2], h)
}

func (p *Prog) actionPath(actionID []byte) string {
	h := hex.EncodeToString(actionID)
	return filepath.Join(p.opts.Dir, "a", h[:2], h)
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
	if err != nil {
		return nil
	}
	size, err1 := strconv.ParseInt(f[2], 10, 64)
	ns, err2 := strconv.ParseInt(f[3], 10, 64)
	if err1 != nil || err2 != nil {
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data := fmt.Sprintf("v1 %x %d %d\n", outputID, size, t.UnixNano())
	return writeAtomic(p.opts.Dir, path, []byte(data))
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
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return dst, nil
}

func (p *Prog) handleGet(ctx context.Context, req *Request) *Response {
	p.Stats.Gets.Add(1)
	if len(req.ActionID) == 0 {
		return &Response{ID: req.ID, Err: "missing action id"}
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
	f, err := os.CreateTemp(filepath.Join(p.opts.Dir, "tmp"), "get-*")
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
	f, err := os.CreateTemp(filepath.Join(p.opts.Dir, "tmp"), "put-*")
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
	if err := p.opts.Remote.Put(ctx, u.actionID, u.outputID, u.blake3, u.size, u.path); err != nil {
		return err
	}
	p.Stats.Uploads.Add(1)
	p.Stats.BytesUp.Add(u.size)
	return nil
}
