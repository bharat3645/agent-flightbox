package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

// DiffResult is the surface delta between a baseline session and a
// candidate session: what the candidate touched that the baseline did not,
// and vice versa. Only additions are treated as a signal worth failing a
// build over (an agent doing less isn't inherently a security concern; an
// agent reaching new binaries, paths or hosts is).
type DiffResult struct {
	NewExecs, RemovedExecs []string
	NewPaths, RemovedPaths []string
	NewNets, RemovedNets   []string
}

// HasNewSurface reports whether the candidate touched anything - a new
// executable, filesystem path, or network destination - that the baseline
// never did.
func (d DiffResult) HasNewSurface() bool {
	return len(d.NewExecs) > 0 || len(d.NewPaths) > 0 || len(d.NewNets) > 0
}

// execIdentity returns the surface identity of an exec event: Comm when the
// sensor captured it, falling back to Exe. Argv is deliberately excluded -
// arguments (ports, tmp paths, request IDs) vary run to run for the same
// legitimate binary, which would make every diff noisy.
func execIdentity(ev session.Event) string {
	if ev.Comm != "" {
		return ev.Comm
	}
	return ev.Exe
}

func eventSet(events []session.Event, kind string, identity func(session.Event) string) map[string]bool {
	set := make(map[string]bool)
	for _, ev := range events {
		if ev.Kind != kind {
			continue
		}
		if id := identity(ev); id != "" {
			set[id] = true
		}
	}
	return set
}

func setDiff(base, cand map[string]bool) (added, removed []string) {
	for id := range cand {
		if !base[id] {
			added = append(added, id)
		}
	}
	for id := range base {
		if !cand[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// Diff compares a baseline session against a candidate session and reports
// the exec/filesystem/network surface each reached that the other didn't.
func Diff(baseline, candidate []session.Event) DiffResult {
	baseExecs := eventSet(baseline, session.KindExec, execIdentity)
	candExecs := eventSet(candidate, session.KindExec, execIdentity)
	basePaths := eventSet(baseline, session.KindFS, func(ev session.Event) string { return ev.Path })
	candPaths := eventSet(candidate, session.KindFS, func(ev session.Event) string { return ev.Path })
	baseNets := eventSet(baseline, session.KindNet, func(ev session.Event) string { return ev.RAddr })
	candNets := eventSet(candidate, session.KindNet, func(ev session.Event) string { return ev.RAddr })

	var d DiffResult
	d.NewExecs, d.RemovedExecs = setDiff(baseExecs, candExecs)
	d.NewPaths, d.RemovedPaths = setDiff(basePaths, candPaths)
	d.NewNets, d.RemovedNets = setDiff(baseNets, candNets)
	return d
}

// DiffText renders a DiffResult as a human-readable report, in the same
// style as Summary.
func DiffText(d DiffResult, baselinePath, candidatePath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flightbox session diff\n")
	fmt.Fprintf(&b, "  baseline:  %s\n", baselinePath)
	fmt.Fprintf(&b, "  candidate: %s\n", candidatePath)

	writeSection := func(name string, added, removed []string) {
		if len(added) == 0 && len(removed) == 0 {
			fmt.Fprintf(&b, "  %s: no change\n", name)
			return
		}
		fmt.Fprintf(&b, "  %s:\n", name)
		for _, id := range added {
			fmt.Fprintf(&b, "    + %s\n", id)
		}
		for _, id := range removed {
			fmt.Fprintf(&b, "    - %s\n", id)
		}
	}
	writeSection("execs", d.NewExecs, d.RemovedExecs)
	writeSection("paths", d.NewPaths, d.RemovedPaths)
	writeSection("net", d.NewNets, d.RemovedNets)

	if d.HasNewSurface() {
		fmt.Fprintf(&b, "  verdict:   candidate reaches new surface (see + lines above)\n")
	} else {
		fmt.Fprintf(&b, "  verdict:   candidate stayed within the baseline's surface\n")
	}
	return b.String()
}
