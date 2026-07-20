// Package proctree tracks a process tree by reading the Linux /proc
// filesystem. It is the unprivileged tier: no capability is required beyond
// being the same user as the observed processes. Its inherent limitation is
// sampling: processes that live for less than one poll interval can be
// missed, and fork cannot be distinguished from exec (both surface as a
// process appearing). The netlink tier (internal/procconn) has neither
// limitation but needs CAP_NET_ADMIN.
package proctree

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

// Proc is one parsed /proc/<pid>/stat snapshot.
type Proc struct {
	PID       int
	Comm      string
	State     string
	PPID      int
	StartTime uint64
}

// ParseStat parses the content of /proc/<pid>/stat. The comm field may
// contain spaces and parentheses; everything between the first '(' and the
// last ')' is comm.
func ParseStat(data []byte) (Proc, error) {
	s := string(data)
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return Proc{}, fmt.Errorf("malformed stat: no comm parentheses")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil {
		return Proc{}, fmt.Errorf("malformed stat pid: %w", err)
	}
	rest := strings.Fields(s[closeIdx+1:])
	// rest[0] = state (field 3), rest[1] = ppid (4), rest[19] = starttime (22).
	if len(rest) < 20 {
		return Proc{}, fmt.Errorf("malformed stat: only %d fields after comm", len(rest))
	}
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return Proc{}, fmt.Errorf("malformed stat ppid: %w", err)
	}
	start, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return Proc{}, fmt.Errorf("malformed stat starttime: %w", err)
	}
	return Proc{PID: pid, Comm: s[open+1 : closeIdx], State: rest[0], PPID: ppid, StartTime: start}, nil
}

// ReadProc reads and parses /proc/<pid>/stat under procRoot.
func ReadProc(procRoot string, pid int) (Proc, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return Proc{}, err
	}
	return ParseStat(b)
}

// Cmdline returns the argv of pid, or nil for kernel threads and vanished
// processes. Arguments are NUL-separated in procfs.
func Cmdline(procRoot string, pid int) []string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil || len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
}

// Exe returns the target of /proc/<pid>/exe, or "" if unreadable.
func Exe(procRoot string, pid int) string {
	t, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return t
}

// ListPIDs returns all numeric entries under procRoot.
func ListPIDs(procRoot string) ([]int, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// MaxArgvBytes bounds how much argv text a single exec event may carry.
const MaxArgvBytes = 8192

// CapArgv truncates argv so the joined byte length stays under MaxArgvBytes.
// The second return value reports whether truncation happened.
func CapArgv(argv []string) ([]string, bool) {
	total := 0
	for i, a := range argv {
		total += len(a) + 1
		if total > MaxArgvBytes {
			out := append([]string{}, argv[:i]...)
			out = append(out, "...(truncated)")
			return out, true
		}
	}
	return argv, false
}

// Tracker maintains the set of pids belonging to the recorded tree.
type Tracker struct {
	procRoot string
	mu       sync.Mutex
	members  map[int]*member
	adopters map[int]bool
}

type member struct {
	exited bool
	comm   string
}

// NewTracker starts tracking rootPID under procRoot.
func NewTracker(procRoot string, rootPID int) *Tracker {
	t := &Tracker{
		procRoot: procRoot,
		members:  map[int]*member{rootPID: {}},
		adopters: map[int]bool{},
	}
	return t
}

// AddAdopter registers a pid (flightbox itself, acting as child subreaper)
// whose direct children count as tree members even after reparenting.
func (t *Tracker) AddAdopter(pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.adopters[pid] = true
}

// Add registers a pid (for example from a netlink fork event). It reports
// whether the pid was new.
func (t *Tracker) Add(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.members[pid]; ok {
		return false
	}
	t.members[pid] = &member{}
	return true
}

// Contains reports whether pid is (or was) part of the tree.
func (t *Tracker) Contains(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.members[pid]
	return ok
}

// MarkExited flags pid as exited, reporting whether this was the first time.
func (t *Tracker) MarkExited(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.members[pid]
	if !ok || m.exited {
		return false
	}
	m.exited = true
	return true
}

// ActivePIDs returns tracked pids not yet marked exited.
func (t *Tracker) ActivePIDs() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]int, 0, len(t.members))
	for pid, m := range t.members {
		if !m.exited {
			out = append(out, pid)
		}
	}
	return out
}

// Poll scans procRoot once. Newly discovered descendants produce exec events
// (sensor "poll", meaning "process observed with this argv"); tracked pids
// that are gone or zombies produce exit events. Exit codes are unknown at
// this tier, so exit events carry none.
func (t *Tracker) Poll() []session.Event {
	pids, err := ListPIDs(t.procRoot)
	if err != nil {
		return nil
	}
	snap := make(map[int]Proc, len(pids))
	for _, pid := range pids {
		if p, err := ReadProc(t.procRoot, pid); err == nil {
			snap[pid] = p
		}
	}
	var evs []session.Event
	t.mu.Lock()
	defer t.mu.Unlock()
	// Exits first: tracked, previously live, now gone or zombie.
	for pid, m := range t.members {
		if m.exited {
			continue
		}
		p, ok := snap[pid]
		if ok && p.State != "Z" && p.State != "X" {
			continue
		}
		m.exited = true
		evs = append(evs, session.Event{Kind: session.KindExit, PID: pid, Comm: m.comm, Sensor: "poll"})
	}
	// Discoveries: any unseen pid whose parent chain reaches the tree.
	for pid, p := range snap {
		if m, ok := t.members[pid]; ok {
			if m.comm == "" {
				m.comm = p.Comm
			}
			continue
		}
		if !t.reachesTreeLocked(pid, snap) {
			continue
		}
		t.members[pid] = &member{comm: p.Comm}
		argv, trunc := CapArgv(Cmdline(t.procRoot, pid))
		evs = append(evs, session.Event{
			Kind: session.KindExec, PID: pid, PPID: p.PPID, Comm: p.Comm,
			Exe: Exe(t.procRoot, pid), Argv: argv, Truncated: trunc, Sensor: "poll",
		})
	}
	return evs
}

// reachesTreeLocked walks the ppid chain in snap until it hits a tracked pid
// or an adopter, or the chain terminates.
func (t *Tracker) reachesTreeLocked(pid int, snap map[int]Proc) bool {
	for hops := 0; hops < 128; hops++ {
		p, ok := snap[pid]
		if !ok {
			return false
		}
		if _, tracked := t.members[p.PPID]; tracked {
			return true
		}
		if t.adopters[p.PPID] {
			return true
		}
		if p.PPID <= 1 {
			return false
		}
		pid = p.PPID
	}
	return false
}
