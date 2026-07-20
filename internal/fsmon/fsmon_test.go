package fsmon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

type collector struct {
	mu  sync.Mutex
	evs []session.Event
}

func (c *collector) emit(ev session.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, ev)
}

func (c *collector) snapshot() []session.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]session.Event, len(c.evs))
	copy(out, c.evs)
	return out
}

// waitFor polls until pred(events) is true or the deadline passes.
func waitFor(t *testing.T, c *collector, what string, pred func([]session.Event) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pred(c.snapshot()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; events: %+v", what, c.snapshot())
}

func hasOp(evs []session.Event, op, path string) bool {
	for _, ev := range evs {
		if ev.Kind == session.KindFS && ev.Op == op && ev.Path == path {
			return true
		}
	}
	return false
}

func hasPath(evs []session.Event, path string) bool {
	for _, ev := range evs {
		if ev.Kind == session.KindFS && ev.Path == path {
			return true
		}
	}
	return false
}

func TestWatcherBasicOps(t *testing.T) {
	root := t.TempDir()
	excluded := filepath.Join(root, "session.jsonl")
	w, err := New([]string{root}, []string{excluded})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	c := &collector{}
	go w.Run(c.emit)

	a := filepath.Join(root, "a.txt")
	if err := os.WriteFile(a, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "create a.txt", func(evs []session.Event) bool {
		return hasOp(evs, "create", a) && hasOp(evs, "close_write", a)
	})

	f, err := os.OpenFile(a, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("two"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	waitFor(t, c, "modify a.txt", func(evs []session.Event) bool {
		return hasOp(evs, "modify", a)
	})

	if err := os.Chmod(a, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "attrib a.txt", func(evs []session.Event) bool {
		return hasOp(evs, "attrib", a)
	})

	b := filepath.Join(root, "b.txt")
	if err := os.Rename(a, b); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "rename a->b", func(evs []session.Event) bool {
		return hasOp(evs, "move_from", a) && hasOp(evs, "move_to", b)
	})

	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "delete b.txt", func(evs []session.Event) bool {
		return hasOp(evs, "delete", b)
	})

	// The excluded path must never appear.
	if err := os.WriteFile(excluded, []byte("secret log"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if hasPath(c.snapshot(), excluded) {
		t.Fatal("excluded path produced events")
	}
}

func TestWatcherNewSubdir(t *testing.T) {
	root := t.TempDir()
	w, err := New([]string{root}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	c := &collector{}
	go w.Run(c.emit)

	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "create sub/", func(evs []session.Event) bool {
		for _, ev := range evs {
			if ev.Kind == session.KindFS && ev.Op == "create" && ev.Path == sub && ev.IsDir {
				return true
			}
		}
		return false
	})

	// Give the watcher a moment to register the new directory, then write
	// inside it: the event must be seen (recursive auto-watch).
	time.Sleep(100 * time.Millisecond)
	inner := filepath.Join(sub, "inner.txt")
	if err := os.WriteFile(inner, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "create sub/inner.txt", func(evs []session.Event) bool {
		return hasPath(evs, inner)
	})
}

func TestWatcherPreexistingTree(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "x", "y")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := New([]string{root}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	c := &collector{}
	go w.Run(c.emit)

	f := filepath.Join(deep, "deep.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, c, "deep file event", func(evs []session.Event) bool {
		return hasPath(evs, f)
	})
}

func TestWatcherBadRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := New([]string{missing}, nil); err == nil {
		t.Fatal("New on a missing root should fail")
	}
}

func TestWatcherCloseIdempotent(t *testing.T) {
	w, err := New([]string{t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := &collector{}
	go w.Run(c.emit)
	time.Sleep(50 * time.Millisecond)
	w.Close()
	w.Close() // must not panic or hang
}

func TestOpFor(t *testing.T) {
	if op := opFor(0); op != "" {
		t.Fatalf("opFor(0) = %q", op)
	}
}
