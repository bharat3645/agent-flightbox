package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	code := 3
	evs := []Event{
		{V: SchemaVersion, Kind: KindSessionStart, Cmd: []string{"echo", "hi"}, RootPID: 42,
			Sensors: map[string]string{"proc": "poll"}},
		{Kind: KindExec, PID: 43, PPID: 42, Comm: "echo", Argv: []string{"echo", "hi"}, Sensor: "poll"},
		{Kind: KindFS, Op: "create", Path: "/tmp/x y/weird\"name", TS: "2026-07-18T00:00:00.5Z"},
		{Kind: KindExit, PID: 43, ExitCode: &code},
		{Kind: KindSessionEnd, Events: 5},
	}
	for _, ev := range evs {
		if err := w.Emit(ev); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if got := w.Written(); got != len(evs) {
		t.Fatalf("Written = %d, want %d", got, len(evs))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close should be nil, got %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file mode = %o, want 0600", perm)
	}

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != len(evs) {
		t.Fatalf("Read %d events, want %d", len(got), len(evs))
	}
	if got[0].Kind != KindSessionStart || got[0].V != SchemaVersion {
		t.Fatalf("bad header: %+v", got[0])
	}
	if got[0].Sensors["proc"] != "poll" {
		t.Fatalf("sensors not preserved: %+v", got[0].Sensors)
	}
	if got[1].TS == "" {
		t.Fatal("TS was not auto-filled")
	}
	if got[2].TS != "2026-07-18T00:00:00.5Z" {
		t.Fatalf("explicit TS not preserved: %q", got[2].TS)
	}
	if got[2].Path != "/tmp/x y/weird\"name" {
		t.Fatalf("path not preserved: %q", got[2].Path)
	}
	if got[3].ExitCode == nil || *got[3].ExitCode != 3 {
		t.Fatalf("exit code not preserved: %+v", got[3])
	}
}

func TestEmitAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Emit(Event{Kind: KindExec}); err == nil {
		t.Fatal("Emit after Close should fail")
	}
}

func TestReadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte("{\"kind\":\"exec\",\"ts\":\"x\"}\nnot json at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(path)
	if err == nil {
		t.Fatal("Read should reject a malformed line")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error should name the line: %v", err)
	}
}

func TestReadSkipsBlankLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(path, []byte("{\"kind\":\"exec\",\"ts\":\"t\"}\n\n{\"kind\":\"exit\",\"ts\":\"t\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evs, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2", len(evs))
	}
}

func TestReadMissingFile(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
		t.Fatal("Read of a missing file should fail")
	}
}
