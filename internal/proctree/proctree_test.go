package proctree

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

// fakeStat builds a minimal but well-formed /proc/<pid>/stat line: state and
// ppid where flightbox reads them, and starttime (field 22) set to 77.
func fakeStat(pid int, comm, state string, ppid int) string {
	return fmt.Sprintf("%d (%s) %s %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 77", pid, comm, state, ppid)
}

func TestParseStat(t *testing.T) {
	p, err := ParseStat([]byte(fakeStat(42, "bash", "S", 1)))
	if err != nil {
		t.Fatalf("ParseStat: %v", err)
	}
	if p.PID != 42 || p.Comm != "bash" || p.State != "S" || p.PPID != 1 || p.StartTime != 77 {
		t.Fatalf("bad parse: %+v", p)
	}
}

func TestParseStatTrickyComm(t *testing.T) {
	// comm may contain spaces and parentheses; parse to the LAST ')'.
	p, err := ParseStat([]byte(fakeStat(7, "(sd-pam) x (y)", "R", 3)))
	if err != nil {
		t.Fatalf("ParseStat: %v", err)
	}
	if p.Comm != "(sd-pam) x (y)" {
		t.Fatalf("comm = %q", p.Comm)
	}
	if p.PPID != 3 || p.State != "R" {
		t.Fatalf("bad parse: %+v", p)
	}
}

func TestParseStatMalformed(t *testing.T) {
	// Empty, no parens, too few fields after comm, and a non-numeric pid.
	cases := []string{
		"",
		"42 no parens here",
		"42 (x) S 1",
		"x (y) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 7",
	}
	for _, c := range cases {
		if _, err := ParseStat([]byte(c)); err == nil {
			t.Fatalf("ParseStat(%q) should fail", c)
		}
	}
}

func TestCapArgv(t *testing.T) {
	small := []string{"a", "b"}
	got, trunc := CapArgv(small)
	if trunc || len(got) != 2 {
		t.Fatalf("small argv should pass through: %v %v", got, trunc)
	}
	huge := []string{"cmd", strings.Repeat("x", MaxArgvBytes)}
	got, trunc = CapArgv(huge)
	if !trunc {
		t.Fatal("huge argv should be truncated")
	}
	if got[len(got)-1] != "...(truncated)" {
		t.Fatalf("missing truncation marker: %v", got)
	}
	over := MaxArgvBytes + 1
	first := []string{strings.Repeat("y", over)}
	got, trunc = CapArgv(first)
	if !trunc || len(got) != 1 || got[0] != "...(truncated)" {
		t.Fatalf("oversized first arg: %v %v", got, trunc)
	}
}

// writeProc creates a fake /proc/<pid> under root.
func writeProc(t *testing.T, root string, pid int, comm, state string, ppid int, cmdline string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fakeStat(pid, comm, state, ppid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if cmdline != "" {
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCmdline(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 9, "x", "S", 1, "python3\x00-c\x00print(1)\x00")
	got := Cmdline(root, 9)
	want := []string{"python3", "-c", "print(1)"}
	if len(got) != len(want) {
		t.Fatalf("Cmdline = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Cmdline = %v, want %v", got, want)
		}
	}
	if Cmdline(root, 12345) != nil {
		t.Fatal("missing pid should yield nil cmdline")
	}
}

func TestListPIDs(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 5, "a", "S", 1, "")
	writeProc(t, root, 17, "b", "S", 1, "")
	if err := os.MkdirAll(filepath.Join(root, "sys"), 0o755); err != nil {
		t.Fatal(err)
	}
	pids, err := ListPIDs(root)
	if err != nil {
		t.Fatalf("ListPIDs: %v", err)
	}
	if len(pids) != 2 {
		t.Fatalf("ListPIDs = %v, want [5 17]", pids)
	}
}

func collectKinds(evs []session.Event) map[string][]int {
	out := map[string][]int{}
	for _, ev := range evs {
		out[ev.Kind] = append(out[ev.Kind], ev.PID)
	}
	return out
}

func TestTrackerDiscoveryAndExit(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, "root-proc", "S", 99, "rootproc\x00")
	tr := NewTracker(root, 100)

	// First poll: root is already a member, nothing new.
	evs := tr.Poll()
	if len(evs) != 0 {
		t.Fatalf("unexpected events on first poll: %+v", evs)
	}

	// A child and a grandchild appear, plus an unrelated process.
	writeProc(t, root, 101, "child", "S", 100, "child\x00--flag\x00")
	writeProc(t, root, 102, "grandchild", "S", 101, "gc\x00")
	writeProc(t, root, 300, "stranger", "S", 200, "stranger\x00")
	evs = tr.Poll()
	kinds := collectKinds(evs)
	if len(kinds[session.KindExec]) != 2 {
		t.Fatalf("want 2 exec events, got %+v", evs)
	}
	for _, ev := range evs {
		if ev.PID == 300 {
			t.Fatal("stranger process must not be tracked")
		}
		if ev.Sensor != "poll" {
			t.Fatalf("sensor should be poll: %+v", ev)
		}
	}
	if !tr.Contains(101) || !tr.Contains(102) || tr.Contains(300) {
		t.Fatal("membership wrong after discovery")
	}

	// Child 101 disappears, grandchild 102 becomes a zombie.
	if err := os.RemoveAll(filepath.Join(root, "101")); err != nil {
		t.Fatal(err)
	}
	writeProc(t, root, 102, "grandchild", "Z", 101, "")
	evs = tr.Poll()
	kinds = collectKinds(evs)
	if len(kinds[session.KindExit]) != 2 {
		t.Fatalf("want 2 exit events, got %+v", evs)
	}
	// Exits are emitted once only.
	if evs := tr.Poll(); len(collectKinds(evs)[session.KindExit]) != 0 {
		t.Fatalf("exit events must not repeat: %+v", evs)
	}

	active := tr.ActivePIDs()
	if len(active) != 1 || active[0] != 100 {
		t.Fatalf("ActivePIDs = %v, want [100]", active)
	}
}

func TestTrackerAdopter(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, "root-proc", "S", 99, "")
	tr := NewTracker(root, 100)
	tr.AddAdopter(555)

	// An orphan reparented to the adopter (flightbox as subreaper).
	writeProc(t, root, 400, "orphan", "S", 555, "orphan\x00")
	evs := tr.Poll()
	kinds := collectKinds(evs)
	if len(kinds[session.KindExec]) != 1 || kinds[session.KindExec][0] != 400 {
		t.Fatalf("adopted orphan should be discovered: %+v", evs)
	}
}

func TestTrackerAddAndMarkExited(t *testing.T) {
	tr := NewTracker(t.TempDir(), 10)
	if !tr.Add(11) || tr.Add(11) {
		t.Fatal("Add should report first-time only")
	}
	if !tr.MarkExited(11) || tr.MarkExited(11) {
		t.Fatal("MarkExited should report first-time only")
	}
	if tr.MarkExited(999) {
		t.Fatal("MarkExited of unknown pid should be false")
	}
}
