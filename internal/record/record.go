// Package record orchestrates a flightbox recording session: it launches
// the child command, runs the sensor tiers appropriate to the current
// privilege level, and serializes everything into one JSONL session file.
package record

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bharat3645/agent-flightbox/internal/fsmon"
	"github.com/bharat3645/agent-flightbox/internal/netmon"
	"github.com/bharat3645/agent-flightbox/internal/procconn"
	"github.com/bharat3645/agent-flightbox/internal/proctree"
	"github.com/bharat3645/agent-flightbox/internal/session"
)

// Process-sensor backend selection.
const (
	BackendAuto    = "auto"
	BackendNetlink = "netlink"
	BackendPoll    = "poll"
)

// ErrExitCode is returned as the exit code when flightbox itself fails.
const ErrExitCode = 125

// prSetChildSubreaper is PR_SET_CHILD_SUBREAPER (linux/prctl.h, since 3.4).
const prSetChildSubreaper = 36

// Options configures a recording.
type Options struct {
	Out      string        // session file (default flightbox-<unixtime>.jsonl)
	Watch    []string      // fs roots (default ["."])
	Backend  string        // auto | netlink | poll
	ProcPoll time.Duration // poll-tier process scan interval
	NetPoll  time.Duration // network scan interval
	NoFS     bool
	NoNet    bool
	Quiet    bool
	ProcRoot string // defaults to /proc; tests may override
}

// Run records argv and returns the child's exit code. A non-nil error means
// flightbox itself failed before the child could be supervised.
func Run(opts Options, argv []string) (int, error) {
	if runtime.GOOS != "linux" {
		return ErrExitCode, fmt.Errorf("flightbox requires linux (procfs, inotify, netlink)")
	}
	if len(argv) == 0 {
		return ErrExitCode, fmt.Errorf("no command given")
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.ProcPoll <= 0 {
		opts.ProcPoll = 25 * time.Millisecond
	}
	if opts.NetPoll <= 0 {
		opts.NetPoll = 50 * time.Millisecond
	}
	if opts.Out == "" {
		opts.Out = fmt.Sprintf("flightbox-%d.jsonl", time.Now().Unix())
	}
	if len(opts.Watch) == 0 {
		opts.Watch = []string{"."}
	}

	w, err := session.Create(opts.Out)
	if err != nil {
		return ErrExitCode, fmt.Errorf("create session file: %w", err)
	}
	defer w.Close()

	var degradations []string
	sensors := map[string]string{}

	// Become a child subreaper so orphaned descendants reparent to
	// flightbox instead of init: the polling tier keeps seeing a
	// connected ppid chain.
	if err := prctlSubreaper(); err != nil {
		degradations = append(degradations,
			"PR_SET_CHILD_SUBREAPER unavailable ("+err.Error()+"): orphaned grandchildren may escape the polling tier")
	}

	// Decide the process-sensor tier.
	var nl *procconn.Conn
	switch opts.Backend {
	case BackendPoll:
		sensors["proc"] = "poll"
	case BackendAuto, BackendNetlink, "":
		conn, reason := probeNetlink()
		if conn != nil {
			nl = conn
			sensors["proc"] = "netlink"
		} else {
			if opts.Backend == BackendNetlink {
				return ErrExitCode, fmt.Errorf("--backend netlink requested but unavailable: %s", reason)
			}
			sensors["proc"] = "poll"
			degradations = append(degradations,
				"netlink proc connector unavailable ("+reason+"): using /proc polling; processes shorter than one interval may be missed")
		}
	default:
		return ErrExitCode, fmt.Errorf("unknown backend %q (valid: auto, netlink, poll)", opts.Backend)
	}
	if nl != nil {
		defer nl.Close()
	}

	// Filesystem sensor.
	var watcher *fsmon.Watcher
	if opts.NoFS {
		sensors["fs"] = "off"
	} else {
		outAbs, _ := filepath.Abs(opts.Out)
		watcher, err = fsmon.New(opts.Watch, []string{outAbs})
		if err != nil {
			sensors["fs"] = "off"
			degradations = append(degradations, "fs sensor disabled: "+err.Error())
			watcher = nil
		} else {
			sensors["fs"] = "inotify"
		}
	}

	if opts.NoNet {
		sensors["net"] = "off"
	} else {
		sensors["net"] = "poll"
	}

	// Event pipeline: sensors emit into a bounded channel; one collector
	// goroutine timestamps and writes. Ordering in the file is write
	// order, so timestamps are non-decreasing by construction.
	events := make(chan session.Event, 4096)
	var dropped atomic.Int64
	emit := func(ev session.Event) {
		select {
		case events <- ev:
		default:
			dropped.Add(1)
		}
	}
	var collectorWG sync.WaitGroup

	// Launch the child.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		if watcher != nil {
			watcher.Close()
		}
		return ErrExitCode, fmt.Errorf("start %q: %w", argv[0], err)
	}
	rootPID := cmd.Process.Pid

	tracker := proctree.NewTracker(opts.ProcRoot, rootPID)
	tracker.AddAdopter(os.Getpid())

	hostname, _ := os.Hostname()
	if err := w.Emit(session.Event{
		V: session.SchemaVersion, Kind: session.KindSessionStart,
		Cmd: argv, RootPID: rootPID, Hostname: hostname,
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		Sensors: sensors, Degradations: degradations,
	}); err != nil {
		return ErrExitCode, fmt.Errorf("write session header: %w", err)
	}

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for ev := range events {
			ev.TS = session.Now()
			_ = w.Emit(ev)
		}
	}()

	if !opts.Quiet {
		fmt.Fprintf(os.Stderr, "flightbox: recording to %s (proc=%s fs=%s net=%s)\n",
			opts.Out, sensors["proc"], sensors["fs"], sensors["net"])
	}

	// The spawn event is exact: we know the argv we just started.
	spawnArgv, spawnTrunc := proctree.CapArgv(argv)
	emit(session.Event{
		Kind: session.KindExec, PID: rootPID, PPID: os.Getpid(),
		Comm: filepath.Base(argv[0]), Exe: argv[0],
		Argv: spawnArgv, Truncated: spawnTrunc, Sensor: "spawn",
	})

	// Sensor loops.
	done := make(chan struct{})
	var sensorWG sync.WaitGroup

	if watcher != nil {
		go watcher.Run(emit) // stopped via watcher.Close()
	}

	if nl != nil {
		sensorWG.Add(1)
		go func() {
			defer sensorWG.Done()
			nlLoop(nl, tracker, opts.ProcRoot, emit, done)
		}()
	} else {
		sensorWG.Add(1)
		go func() {
			defer sensorWG.Done()
			tick := time.NewTicker(opts.ProcPoll)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					for _, ev := range tracker.Poll() {
						emit(ev)
					}
				}
			}
		}()
	}

	var poller *netmon.Poller
	if !opts.NoNet {
		poller = netmon.NewPoller(opts.ProcRoot, tracker.ActivePIDs)
		sensorWG.Add(1)
		go func() {
			defer sensorWG.Done()
			tick := time.NewTicker(opts.NetPoll)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					for _, ev := range poller.Poll() {
						emit(ev)
					}
				}
			}
		}()
	}

	// Supervise the child, forwarding INT/TERM.
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	waitc := make(chan error, 1)
	go func() { waitc <- cmd.Wait() }()
	var waitErr error
waitLoop:
	for {
		select {
		case sig := <-sigc:
			_ = cmd.Process.Signal(sig)
		case waitErr = <-waitc:
			break waitLoop
		}
	}
	signal.Stop(sigc)

	childCode := ErrExitCode
	if cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			childCode = decodeWaitStatus(ws)
		} else {
			childCode = cmd.ProcessState.ExitCode()
		}
	} else if waitErr != nil {
		emit(session.Event{Kind: session.KindSensorError, Sensor: "record", Error: "wait: " + waitErr.Error()})
	}
	tracker.MarkExited(rootPID)

	// Let periodic sensors observe the final state, then stop them.
	settle := opts.NetPoll
	if nl == nil && opts.ProcPoll > settle {
		settle = opts.ProcPoll
	}
	settle += 20 * time.Millisecond
	time.Sleep(settle)
	close(done)
	if watcher != nil {
		watcher.Close()
	}
	sensorWG.Wait()

	// Final sweeps from this goroutine (sensor goroutines are stopped, so
	// tracker/poller access is race-free).
	if nl == nil {
		for _, ev := range tracker.Poll() {
			emit(ev)
		}
	}
	reapOrphans(tracker, emit)

	emit(session.Event{Kind: session.KindChildExit, PID: rootPID, ExitCode: &childCode})

	close(events)
	collectorWG.Wait()

	total := w.Written() + 1 // count includes the session_end line itself
	endEv := session.Event{
		Kind: session.KindSessionEnd, Events: total, Dropped: int(dropped.Load()),
	}
	if err := w.Emit(endEv); err != nil {
		return childCode, fmt.Errorf("write session trailer: %w", err)
	}
	if err := w.Close(); err != nil {
		return childCode, fmt.Errorf("close session file: %w", err)
	}
	if !opts.Quiet {
		fmt.Fprintf(os.Stderr, "flightbox: %d events recorded to %s (child exit %d)\n",
			total, opts.Out, childCode)
	}
	return childCode, nil
}

// nlLoop consumes netlink proc events, filtering to the tracked tree.
func nlLoop(nl *procconn.Conn, tracker *proctree.Tracker, procRoot string, emit func(session.Event), done chan struct{}) {
	buf := make([]byte, 256*1024)
	for {
		select {
		case <-done:
			return
		default:
		}
		evs, err := nl.Receive(buf) // 200ms socket timeout: (nil, nil)
		if err != nil {
			emit(session.Event{Kind: session.KindSensorError, Sensor: "netlink", Error: err.Error()})
			return
		}
		for _, re := range evs {
			switch re.What {
			case procconn.WhatFork:
				if tracker.Contains(re.PPID) && tracker.Add(re.PID) {
					emit(session.Event{Kind: session.KindFork, PID: re.PID, PPID: re.PPID, Sensor: "netlink"})
				}
			case procconn.WhatExec:
				if tracker.Contains(re.PID) {
					argv, trunc := proctree.CapArgv(proctree.Cmdline(procRoot, re.PID))
					comm := ""
					if p, perr := proctree.ReadProc(procRoot, re.PID); perr == nil {
						comm = p.Comm
					}
					emit(session.Event{
						Kind: session.KindExec, PID: re.PID, Comm: comm,
						Exe: proctree.Exe(procRoot, re.PID),
						Argv: argv, Truncated: trunc, Sensor: "netlink",
					})
				}
			case procconn.WhatExit:
				if tracker.Contains(re.PID) && tracker.MarkExited(re.PID) {
					code := decodeWaitStatus(syscall.WaitStatus(re.ExitCode))
					emit(session.Event{Kind: session.KindExit, PID: re.PID, ExitCode: &code, Sensor: "netlink"})
				}
			}
		}
	}
}

// probeNetlink dials the connector and verifies events actually arrive
// (the kernel accepts subscriptions from unprivileged users but silently
// never delivers). A short-lived helper process guarantees at least one
// event system-wide if delivery works.
func probeNetlink() (*procconn.Conn, string) {
	conn, err := procconn.Dial()
	if err != nil {
		return nil, err.Error()
	}
	if err := exec.Command("/bin/true").Run(); err != nil {
		_ = exec.Command("/usr/bin/true").Run()
	}
	buf := make([]byte, 64*1024)
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		evs, rerr := conn.Receive(buf)
		if rerr != nil {
			conn.Close()
			return nil, "receive: " + rerr.Error()
		}
		if len(evs) > 0 {
			return conn, ""
		}
	}
	conn.Close()
	return nil, "subscribed but no events delivered (needs root / CAP_NET_ADMIN)"
}

// ProbeNetlink reports whether the netlink proc-events tier works at the
// current privilege level. Used by "flightbox check".
func ProbeNetlink() (bool, string) {
	conn, reason := probeNetlink()
	if conn != nil {
		conn.Close()
		return true, ""
	}
	return false, reason
}

// prctlSubreaper marks this process as a child subreaper.
func prctlSubreaper() error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		return errno
	}
	return nil
}

// reapOrphans collects zombies reparented to flightbox (it is a subreaper)
// after the direct child has been waited on, emitting exit events for tree
// members no sensor had recorded yet.
func reapOrphans(tracker *proctree.Tracker, emit func(session.Event)) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err != nil || pid <= 0 {
			return
		}
		if tracker.Contains(pid) && tracker.MarkExited(pid) {
			code := decodeWaitStatus(ws)
			emit(session.Event{Kind: session.KindExit, PID: pid, ExitCode: &code, Sensor: "reap"})
		}
	}
}

// decodeWaitStatus turns a wait status into a shell-style exit code
// (128+signal for signal deaths).
func decodeWaitStatus(ws syscall.WaitStatus) int {
	switch {
	case ws.Exited():
		return ws.ExitStatus()
	case ws.Signaled():
		return 128 + int(ws.Signal())
	default:
		return int(ws)
	}
}
