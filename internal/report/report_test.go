package report

import (
	"strings"
	"testing"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

func exitCode(c int) *int { return &c }

func sampleSession() []session.Event {
	return []session.Event{
		{V: 1, Kind: session.KindSessionStart, TS: "2026-07-18T10:00:00Z",
			Cmd: []string{"bash", "-c", "workload"}, RootPID: 100,
			Sensors:      map[string]string{"proc": "poll", "fs": "inotify", "net": "poll"},
			Degradations: []string{"netlink proc connector unavailable (test): using /proc polling"}},
		{Kind: session.KindExec, TS: "2026-07-18T10:00:00.05Z", PID: 100, PPID: 50,
			Comm: "bash", Argv: []string{"bash", "-c", "workload"}, Sensor: "spawn"},
		{Kind: session.KindExec, TS: "2026-07-18T10:00:00.2Z", PID: 101, PPID: 100,
			Comm: "python3", Argv: []string{"python3", "-c", "connect()"}, Sensor: "poll"},
		{Kind: session.KindFork, TS: "2026-07-18T10:00:00.3Z", PID: 102, PPID: 100, Sensor: "netlink"},
		{Kind: session.KindFS, TS: "2026-07-18T10:00:00.4Z", Op: "create", Path: "/w/hello.txt", Sensor: "inotify"},
		{Kind: session.KindFS, TS: "2026-07-18T10:00:00.45Z", Op: "close_write", Path: "/w/hello.txt", Sensor: "inotify"},
		{Kind: session.KindNet, TS: "2026-07-18T10:00:00.5Z", PID: 101, Proto: "tcp", Family: 4,
			LAddr: "127.0.0.1:33000", RAddr: "127.0.0.1:9999", Sensor: "poll"},
		{Kind: session.KindExit, TS: "2026-07-18T10:00:00.9Z", PID: 101, ExitCode: exitCode(0), Sensor: "poll"},
		{Kind: session.KindChildExit, TS: "2026-07-18T10:00:01Z", PID: 100, ExitCode: exitCode(7)},
		{Kind: session.KindSessionEnd, TS: "2026-07-18T10:00:01.1Z", Events: 10, Dropped: 0},
	}
}

func TestSummary(t *testing.T) {
	s := Summary(sampleSession())
	for _, want := range []string{
		"cmd:        bash -c workload",
		"backend:    fs=inotify net=poll proc=poll",
		"degraded:   netlink proc connector unavailable",
		"processes:  3 observed (2 exec, 1 fork, 1 exit)",
		"files:      2 events across 1 paths (close_write 1, create 1)",
		"network:    1 connections (tcp 1, udp 0)",
		"tcp 127.0.0.1:9999 (pid 101)",
		"child exit: 7",
		"events:     10 written, 0 dropped",
		"duration:   1.1s",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary missing %q:\n%s", want, s)
		}
	}
}

func TestSummaryEmpty(t *testing.T) {
	s := Summary(nil)
	if !strings.Contains(s, "session_end missing") {
		t.Fatalf("empty summary should flag missing trailer:\n%s", s)
	}
}

func TestHTML(t *testing.T) {
	out, err := HTML(sampleSession(), "0.1.0")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	h := string(out)
	for _, want := range []string{
		"<title>flightbox session</title>",
		"bash -c workload",
		"127.0.0.1:9999",
		"/w/hello.txt",
		"pid 101",
		"child exit:</b> 7",
		"degraded: netlink proc connector unavailable",
		"no scripts, no external assets",
		"flightbox 0.1.0",
	} {
		if !strings.Contains(h, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if strings.Contains(h, "<script") {
		t.Fatal("report must not contain scripts")
	}
	if strings.Contains(h, "src=\"http") || strings.Contains(h, "href=\"http") {
		t.Fatal("report must not reference external assets")
	}
}

func TestHTMLEscapesHostileContent(t *testing.T) {
	evs := []session.Event{
		{V: 1, Kind: session.KindSessionStart, TS: "2026-07-18T10:00:00Z",
			Cmd: []string{"sh", "-c", "<script>alert(1)</script>"}, RootPID: 1,
			Sensors: map[string]string{"proc": "poll"}},
		{Kind: session.KindFS, TS: "2026-07-18T10:00:00.1Z", Op: "create",
			Path: "/tmp/<img src=x onerror=alert(2)>.txt", Sensor: "inotify"},
		{Kind: session.KindSessionEnd, TS: "2026-07-18T10:00:01Z", Events: 3},
	}
	out, err := HTML(evs, "0.1.0")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	h := string(out)
	if strings.Contains(h, "<script>alert(1)</script>") {
		t.Fatal("cmd was not escaped")
	}
	if strings.Contains(h, "<img src=x") {
		t.Fatal("path was not escaped")
	}
}

func TestHTMLEmptySession(t *testing.T) {
	out, err := HTML(nil, "0.1.0")
	if err != nil {
		t.Fatalf("HTML on empty session: %v", err)
	}
	if !strings.Contains(string(out), "none observed") {
		t.Fatal("empty session should render 'none observed' sections")
	}
}

func TestEventLineFormats(t *testing.T) {
	ev := session.Event{Kind: session.KindNet, TS: "2026-07-18T10:00:00.5Z",
		PID: 5, Proto: "tcp", RAddr: "1.2.3.4:443"}
	line := eventLine(ev)
	if !strings.Contains(line, "net") || !strings.Contains(line, "1.2.3.4:443") {
		t.Fatalf("eventLine: %q", line)
	}
	unk := eventLine(session.Event{Kind: "future_kind", TS: "2026-07-18T10:00:00Z"})
	if !strings.Contains(unk, "future_kind") {
		t.Fatalf("unknown kind line: %q", unk)
	}
}
