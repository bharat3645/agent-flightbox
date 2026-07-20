// Command flightbox is a flight recorder for AI agents (or any process
// tree): it records processes started, files touched and network egress
// into a JSONL session file, and renders static HTML timeline reports.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bharat3645/agent-flightbox/internal/fsmon"
	"github.com/bharat3645/agent-flightbox/internal/netmon"
	"github.com/bharat3645/agent-flightbox/internal/proctree"
	"github.com/bharat3645/agent-flightbox/internal/record"
	"github.com/bharat3645/agent-flightbox/internal/report"
	"github.com/bharat3645/agent-flightbox/internal/session"
)

const version = "0.1.0"

const usageText = `flightbox %s - a flight recorder for AI agents

Records what a process tree actually did: processes started, files touched,
network egress. Output is a JSONL session file plus static reports.

Usage:
  flightbox record [flags] -- <command> [args...]   record a session
  flightbox summary <session.jsonl>                 one-screen text digest
  flightbox report [-o out.html] <session.jsonl>    static HTML timeline
  flightbox check                                   probe sensor availability
  flightbox version                                 print version

Record flags:
  -o FILE          session output file
                   (default flightbox-<unixtime>.jsonl, created mode 0600)
  -watch DIR       watch DIR recursively for file activity
                   (repeatable; default: current directory)
  -backend MODE    auto | netlink | poll (default auto: netlink needs root,
                   flightbox degrades to /proc polling and says so)
  -proc-poll DUR   process poll interval in poll mode (default 25ms)
  -net-poll DUR    network poll interval (default 50ms)
  -no-fs           disable the filesystem sensor
  -no-net          disable the network sensor
  -quiet           suppress flightbox status lines on stderr

Exit status: record exits with the child's exit code; %d means flightbox
itself failed. Linux only (procfs + inotify; netlink proc events as root).
`

func usage() {
	fmt.Fprintf(os.Stderr, usageText, version, record.ErrExitCode)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "record":
		return cmdRecord(args[1:])
	case "summary":
		return cmdSummary(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "check":
		return cmdCheck()
	case "version", "-v", "--version":
		fmt.Println("flightbox " + version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	}
	fmt.Fprintf(os.Stderr, "flightbox: unknown command %q (try: flightbox help)\n", args[0])
	return 2
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func cmdRecord(args []string) int {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("o", "", "session output file")
	var watch multiFlag
	fs.Var(&watch, "watch", "directory to watch recursively (repeatable)")
	backend := fs.String("backend", record.BackendAuto, "auto | netlink | poll")
	procPoll := fs.Duration("proc-poll", 25*time.Millisecond, "process poll interval")
	netPoll := fs.Duration("net-poll", 50*time.Millisecond, "network poll interval")
	noFS := fs.Bool("no-fs", false, "disable filesystem sensor")
	noNet := fs.Bool("no-net", false, "disable network sensor")
	quiet := fs.Bool("quiet", false, "suppress status lines")
	if err := fs.Parse(args); err != nil {
		return record.ErrExitCode
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "flightbox record: no command given")
		fmt.Fprintln(os.Stderr, "usage: flightbox record [flags] -- <command> [args...]")
		return record.ErrExitCode
	}
	code, err := record.Run(record.Options{
		Out:      *out,
		Watch:    watch,
		Backend:  *backend,
		ProcPoll: *procPoll,
		NetPoll:  *netPoll,
		NoFS:     *noFS,
		NoNet:    *noNet,
		Quiet:    *quiet,
	}, argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flightbox record: %v\n", err)
	}
	return code
}

func cmdSummary(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: flightbox summary <session.jsonl>")
		return 2
	}
	events, err := session.Read(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "flightbox summary: %v\n", err)
		return 1
	}
	fmt.Print(report.Summary(events))
	return 0
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("o", "", "output HTML file (default <session>.html)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: flightbox report [-o out.html] <session.jsonl>")
		return 2
	}
	events, err := session.Read(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "flightbox report: %v\n", err)
		return 1
	}
	html, err := report.HTML(events, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flightbox report: %v\n", err)
		return 1
	}
	dst := *out
	if dst == "" {
		dst = strings.TrimSuffix(rest[0], ".jsonl") + ".html"
	}
	if err := os.WriteFile(dst, html, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "flightbox report: %v\n", err)
		return 1
	}
	fmt.Printf("flightbox: report written to %s\n", dst)
	return 0
}

func cmdCheck() int {
	fmt.Printf("flightbox %s sensor availability\n", version)
	if runtime.GOOS != "linux" {
		fmt.Printf("  os:       %s (flightbox requires linux)\n", runtime.GOOS)
		return 1
	}
	fmt.Printf("  os:       linux ok\n")

	if _, err := proctree.ReadProc("/proc", os.Getpid()); err == nil {
		fmt.Printf("  procfs:   ok\n")
	} else {
		fmt.Printf("  procfs:   unavailable (%v)\n", err)
	}

	if _, err := netmon.ReadTable("/proc", "tcp"); err == nil {
		fmt.Printf("  proc_net: ok\n")
	} else {
		fmt.Printf("  proc_net: unavailable (%v)\n", err)
	}

	if w, err := fsmon.New([]string{os.TempDir()}, nil); err == nil {
		w.Close()
		fmt.Printf("  inotify:  ok\n")
	} else {
		fmt.Printf("  inotify:  unavailable (%v)\n", err)
	}

	if ok, reason := record.ProbeNetlink(); ok {
		fmt.Printf("  netlink:  ok (exact fork/exec/exit events)\n")
	} else {
		fmt.Printf("  netlink:  unavailable (%s)\n", reason)
		fmt.Printf("            recordings will use /proc polling; run as root for netlink\n")
	}
	return 0
}
