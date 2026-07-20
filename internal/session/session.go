// Package session defines the flightbox session event model and the JSONL
// writer/reader. One session is one JSONL file: a session_start header, a
// stream of observation events, and a session_end trailer.
//
// Privacy stance: flightbox records behavioral metadata only. Paths, argv,
// process names and socket addresses are recorded (that is the point of a
// flight recorder); file contents, network payloads and environment variable
// values are never read by the sensors, let alone written.
package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// SchemaVersion is written in the session_start record as "v".
const SchemaVersion = 1

// Event kinds.
const (
	KindSessionStart = "session_start"
	KindExec         = "exec"
	KindFork         = "fork"
	KindExit         = "exit"
	KindFS           = "fs"
	KindNet          = "net"
	KindChildExit    = "child_exit"
	KindSensorError  = "sensor_error"
	KindSessionEnd   = "session_end"
)

// Event is a single JSONL record. Kind-specific fields are omitempty so each
// line carries only what its kind needs.
type Event struct {
	V    int    `json:"v,omitempty"`
	Kind string `json:"kind"`
	TS   string `json:"ts"`

	// Process fields (exec / fork / exit / child_exit).
	PID       int      `json:"pid,omitempty"`
	PPID      int      `json:"ppid,omitempty"`
	Comm      string   `json:"comm,omitempty"`
	Exe       string   `json:"exe,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	ExitCode  *int     `json:"exit_code,omitempty"`

	// Filesystem fields (fs).
	Op    string `json:"op,omitempty"`
	Path  string `json:"path,omitempty"`
	IsDir bool   `json:"dir,omitempty"`

	// Network fields (net).
	Proto  string `json:"proto,omitempty"`
	Family int    `json:"family,omitempty"`
	LAddr  string `json:"laddr,omitempty"`
	RAddr  string `json:"raddr,omitempty"`

	// Provenance and diagnostics.
	Sensor string `json:"sensor,omitempty"`
	Error  string `json:"error,omitempty"`

	// session_start extras.
	Cmd          []string          `json:"cmd,omitempty"`
	RootPID      int               `json:"root_pid,omitempty"`
	Hostname     string            `json:"hostname,omitempty"`
	OS           string            `json:"os,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Sensors      map[string]string `json:"sensors,omitempty"`
	Degradations []string          `json:"degradations,omitempty"`

	// session_end extras.
	Events  int `json:"events,omitempty"`
	Dropped int `json:"dropped,omitempty"`
}

// Now returns the canonical flightbox timestamp: RFC 3339, nanoseconds, UTC.
func Now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// Writer appends events to a JSONL file created with 0600 permissions.
// It is safe for concurrent use.
type Writer struct {
	mu      sync.Mutex
	f       *os.File
	bw      *bufio.Writer
	written int
	closed  bool
}

// Create opens (truncating) path with 0600 permissions. If the file already
// existed with looser permissions they are tightened.
func Create(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{f: f, bw: bufio.NewWriterSize(f, 64*1024)}, nil
}

// Emit writes one event as a JSON line. A missing TS is filled with Now().
func (w *Writer) Emit(ev Event) error {
	if ev.TS == "" {
		ev.TS = Now()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fmt.Errorf("session writer is closed")
	}
	if _, err := w.bw.Write(b); err != nil {
		return err
	}
	if err := w.bw.WriteByte('\n'); err != nil {
		return err
	}
	w.written++
	return nil
}

// Written returns the number of events emitted so far.
func (w *Writer) Written() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

// Close flushes and closes the underlying file. It is idempotent.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// Read loads a session file. Lines longer than 4 MiB are an error.
func Read(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, ln, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
