package client

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Wire types for the GOCACHEPROG protocol. These mirror
// cmd/go/internal/cacheprog, which cannot be imported.

type Cmd string

const (
	CmdGet   Cmd = "get"
	CmdPut   Cmd = "put"
	CmdClose Cmd = "close"
)

type Request struct {
	ID       int64
	Command  Cmd
	ActionID []byte `json:",omitempty"`
	OutputID []byte `json:",omitempty"`
	BodySize int64  `json:",omitempty"`
}

type Response struct {
	ID            int64
	Err           string     `json:",omitempty"`
	KnownCommands []Cmd      `json:",omitempty"`
	Miss          bool       `json:",omitempty"`
	OutputID      []byte     `json:",omitempty"`
	Size          int64      `json:",omitempty"`
	Time          *time.Time `json:",omitempty"`
	DiskPath      string     `json:",omitempty"`
}

// reader decodes requests from the go command. A put with BodySize > 0 is
// followed by a JSON string of base64 on its own line.
type reader struct {
	br *bufio.Reader
}

func newReader(r io.Reader) *reader { return &reader{br: bufio.NewReaderSize(r, 64<<10)} }

func (r *reader) skipSpace() error {
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return err
		}
		if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
			return r.br.UnreadByte()
		}
	}
}

// next reads the next request header. io.EOF means stdin closed.
func (r *reader) next() (*Request, error) {
	if err := r.skipSpace(); err != nil {
		return nil, err
	}
	line, err := r.br.ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(bytes.TrimSpace(line), &req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	return &req, nil
}

// body streams the base64 body of a put into w and returns the decoded size.
func (r *reader) body(w io.Writer) (int64, error) {
	if err := r.skipSpace(); err != nil {
		return 0, err
	}
	q, err := r.br.ReadByte()
	if err != nil {
		return 0, err
	}
	if q != '"' {
		return 0, fmt.Errorf("expected '\"' before body, got %q", q)
	}
	qr := &quotedReader{br: r.br}
	n, err := io.Copy(w, base64.NewDecoder(base64.StdEncoding, qr))
	if err != nil {
		return n, fmt.Errorf("decode body: %w", err)
	}
	if !qr.done {
		return n, errors.New("body not terminated")
	}
	return n, nil
}

// quotedReader returns bytes up to (not including) the closing quote.
type quotedReader struct {
	br   *bufio.Reader
	done bool
}

func (q *quotedReader) Read(p []byte) (int, error) {
	if q.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Block for at least one byte, then use only what is buffered.
	if _, err := q.br.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, err
	}
	chunk, _ := q.br.Peek(min(q.br.Buffered(), len(p)))
	if i := bytes.IndexByte(chunk, '"'); i >= 0 {
		n := copy(p, chunk[:i])
		q.br.Discard(i + 1) //nolint:errcheck
		q.done = true
		return n, nil
	}
	n := copy(p, chunk)
	q.br.Discard(n) //nolint:errcheck
	return n, nil
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
