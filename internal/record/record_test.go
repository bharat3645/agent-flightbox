package record

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

func TestDecodeWaitStatus(t *testing.T) {
	// Raw wait statuses: exit(0), exit(1), killed by SIGKILL(9).
	cases := []struct {
		raw  uint32
		want int
	}{
		{0x0000, 0},
		{0x0100, 1},
		{0x0009, 137},
	}
	for _, c := range cases {
		if got := decodeWaitStatus(syscall.WaitStatus(c.raw)); got != c.want {
			t.Fatalf("decodeWaitStatus(%#x) = %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	out := filepath.Join(t.TempDir(), "s.jsonl")
	if _, err := Run(Options{Out: out, Backend: "warp-drive", Quiet: true}, []string{"true"}); err == nil {
		t.Fatal("unknown backend should error")
	}
	if _, err := Run(Options{Out: out, Quiet: true}, nil); err == nil {
		t.Fatal("empty argv should error")
	}
	code, err := Run(Options{Out: out, Backend: BackendPoll, Quiet: true}, []string{"/nonexistent-flightbox-test-binary"})
	if err == nil {
		t.Fatal("unstartable child should error")
	}
	if code != ErrExitCode {
		t.Fatalf("code = %d, want %d", code, ErrExitCode)
	}
}

func findEvent(evs []session.Event, pred func(session.Event) bool) *session.Event {
	for i := range evs {
		if pred(evs[i]) {
			return &evs[i]
		}
	}
	return nil
}

func TestRecordEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash required")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 required")
	}

	dir := t.TempDir()
	watch := filepath.Join(dir, "w")
	if err := os.Mkdir(watch, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "s.jsonl")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}(conn)
		}
	}()

	t.Setenv("FB_W", watch)
	t.Setenv("FB_PORT", fmt.Sprint(port))

	script := `
set -e
echo hello > "$FB_W/hello.txt"
echo more >> "$FB_W/hello.txt"
mkdir "$FB_W/sub"
sleep 0.1
echo x > "$FB_W/sub/inner.txt"
rm "$FB_W/hello.txt"
python3 -c '
import os, socket, time
s = socket.create_connection(("127.0.0.1", int(os.environ["FB_PORT"])))
time.sleep(0.5)
s.close()
'
bash -c "sleep 0.2"
exit 7
`
	code, err := Run(Options{
		Out:      out,
		Watch:    []string{watch},
		Backend:  BackendPoll,
		ProcPoll: 15 * time.Millisecond,
		NetPoll:  15 * time.Millisecond,
		Quiet:    true,
	}, []string{"bash", "-c", script})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 7 {
		t.Fatalf("child exit code = %d, want 7", code)
	}

	st, err := os.Stat(out)
	if err != nil {
		t.Fatalf("session file: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file mode = %o, want 0600", perm)
	}

	evs, err := session.Read(out)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(evs) < 8 {
		t.Fatalf("suspiciously few events: %d", len(evs))
	}

	start := evs[0]
	if start.Kind != session.KindSessionStart || start.V != session.SchemaVersion {
		t.Fatalf("first event is not a v1 session_start: %+v", start)
	}
	if start.Sensors["proc"] != "poll" || start.Sensors["fs"] != "inotify" || start.Sensors["net"] != "poll" {
		t.Fatalf("sensors wrong: %+v", start.Sensors)
	}
	if start.RootPID <= 0 {
		t.Fatal("root pid missing")
	}

	end := evs[len(evs)-1]
	if end.Kind != session.KindSessionEnd {
		t.Fatalf("last event is not session_end: %+v", end)
	}
	if end.Events != len(evs) {
		t.Fatalf("session_end.events = %d, file has %d lines", end.Events, len(evs))
	}
	if end.Dropped != 0 {
		t.Fatalf("events were dropped: %d", end.Dropped)
	}

	// Spawn event: exact argv, root pid.
	spawn := findEvent(evs, func(ev session.Event) bool { return ev.Sensor == "spawn" })
	if spawn == nil || spawn.PID != start.RootPID || spawn.Kind != session.KindExec {
		t.Fatalf("spawn event wrong: %+v", spawn)
	}
	if len(spawn.Argv) == 0 || spawn.Argv[0] != "bash" {
		t.Fatalf("spawn argv wrong: %+v", spawn.Argv)
	}

	// The polling tier must have caught the longer-lived descendants.
	py := findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindExec && strings.Contains(strings.Join(ev.Argv, " "), "python3")
	})
	if py == nil {
		t.Fatal("python3 exec not observed")
	}
	sleeper := findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindExec && strings.Contains(strings.Join(ev.Argv, " "), "sleep 0.2")
	})
	if sleeper == nil {
		t.Fatal("grandchild bash sleep not observed")
	}
	pids := map[int]bool{}
	for _, ev := range evs {
		if ev.Kind == session.KindExec {
			pids[ev.PID] = true
		}
	}
	if len(pids) < 3 {
		t.Fatalf("want >= 3 distinct exec pids, got %v", pids)
	}

	// Filesystem evidence.
	hello := filepath.Join(watch, "hello.txt")
	if findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindFS && ev.Path == hello && (ev.Op == "create" || ev.Op == "close_write")
	}) == nil {
		t.Fatal("hello.txt write not observed")
	}
	if findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindFS && ev.Path == hello && ev.Op == "delete"
	}) == nil {
		t.Fatal("hello.txt delete not observed")
	}
	sub := filepath.Join(watch, "sub")
	if findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindFS && ev.Path == sub && ev.Op == "create" && ev.IsDir
	}) == nil {
		t.Fatal("sub/ mkdir not observed")
	}
	inner := filepath.Join(sub, "inner.txt")
	if findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindFS && ev.Path == inner
	}) == nil {
		t.Fatal("sub/inner.txt not observed (recursive watch failed)")
	}

	// Network evidence.
	raddr := fmt.Sprintf("127.0.0.1:%d", port)
	netEv := findEvent(evs, func(ev session.Event) bool {
		return ev.Kind == session.KindNet && ev.RAddr == raddr && ev.Proto == "tcp"
	})
	if netEv == nil {
		t.Fatalf("connection to %s not observed", raddr)
	}
	if netEv.PID <= 0 {
		t.Fatalf("net event has no pid: %+v", netEv)
	}

	// Exit evidence.
	if findEvent(evs, func(ev session.Event) bool { return ev.Kind == session.KindExit }) == nil {
		t.Fatal("no exit events observed")
	}
	childExit := findEvent(evs, func(ev session.Event) bool { return ev.Kind == session.KindChildExit })
	if childExit == nil || childExit.ExitCode == nil || *childExit.ExitCode != 7 {
		t.Fatalf("child_exit wrong: %+v", childExit)
	}

	// Timestamps: non-decreasing (single-writer ordering), small tolerance.
	var prev time.Time
	for i, ev := range evs {
		ts, perr := time.Parse(time.RFC3339Nano, ev.TS)
		if perr != nil {
			t.Fatalf("event %d has bad timestamp %q: %v", i, ev.TS, perr)
		}
		if !prev.IsZero() && ts.Before(prev.Add(-5*time.Millisecond)) {
			t.Fatalf("timestamps regress at event %d: %s < %s", i, ev.TS, prev)
		}
		if ts.After(prev) {
			prev = ts
		}
	}

	// The session log itself must not appear in fs events (excluded), and
	// no sensor may ever record environment values.
	for _, ev := range evs {
		if ev.Kind == session.KindFS && ev.Path == out {
			t.Fatal("session log leaked into fs events")
		}
	}
}

func TestRecordNoSensors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	out := filepath.Join(t.TempDir(), "s.jsonl")
	code, err := Run(Options{
		Out: out, Backend: BackendPoll, NoFS: true, NoNet: true,
		ProcPoll: 10 * time.Millisecond, Quiet: true,
	}, []string{"/bin/sh", "-c", "exit 0"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	evs, err := session.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if evs[0].Sensors["fs"] != "off" || evs[0].Sensors["net"] != "off" {
		t.Fatalf("sensors should be off: %+v", evs[0].Sensors)
	}
	for _, ev := range evs {
		if ev.Kind == session.KindFS || ev.Kind == session.KindNet {
			t.Fatalf("disabled sensor produced event: %+v", ev)
		}
	}
}
