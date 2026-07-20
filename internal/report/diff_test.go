package report

import (
	"strings"
	"testing"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

func execEv(comm string) session.Event {
	return session.Event{Kind: session.KindExec, Comm: comm}
}

func fsEv(path string) session.Event {
	return session.Event{Kind: session.KindFS, Op: "create", Path: path}
}

func netEv(raddr string) session.Event {
	return session.Event{Kind: session.KindNet, RAddr: raddr}
}

func TestDiffIdenticalSessionsHaveNoNewSurface(t *testing.T) {
	s := sampleSession()
	d := Diff(s, s)
	if d.HasNewSurface() {
		t.Fatalf("identical sessions reported new surface: %+v", d)
	}
	if len(d.NewExecs) != 0 || len(d.NewPaths) != 0 || len(d.NewNets) != 0 {
		t.Fatalf("expected no additions, got %+v", d)
	}
}

func TestDiffDetectsNewExecPathAndNet(t *testing.T) {
	baseline := []session.Event{execEv("bash"), fsEv("/w/a.txt"), netEv("10.0.0.1:80")}
	candidate := []session.Event{
		execEv("bash"), execEv("curl"),
		fsEv("/w/a.txt"), fsEv("/etc/passwd"),
		netEv("10.0.0.1:80"), netEv("evil.example:443"),
	}
	d := Diff(baseline, candidate)
	if !d.HasNewSurface() {
		t.Fatal("expected new surface to be detected")
	}
	if len(d.NewExecs) != 1 || d.NewExecs[0] != "curl" {
		t.Fatalf("NewExecs = %v, want [curl]", d.NewExecs)
	}
	if len(d.NewPaths) != 1 || d.NewPaths[0] != "/etc/passwd" {
		t.Fatalf("NewPaths = %v, want [/etc/passwd]", d.NewPaths)
	}
	if len(d.NewNets) != 1 || d.NewNets[0] != "evil.example:443" {
		t.Fatalf("NewNets = %v, want [evil.example:443]", d.NewNets)
	}
}

func TestDiffCandidateDoingLessIsNotNewSurface(t *testing.T) {
	baseline := []session.Event{execEv("bash"), execEv("curl"), fsEv("/w/a.txt")}
	candidate := []session.Event{execEv("bash")}
	d := Diff(baseline, candidate)
	if d.HasNewSurface() {
		t.Fatalf("candidate touching strictly less should not be new surface: %+v", d)
	}
	if len(d.RemovedExecs) != 1 || d.RemovedExecs[0] != "curl" {
		t.Fatalf("RemovedExecs = %v, want [curl]", d.RemovedExecs)
	}
	if len(d.RemovedPaths) != 1 || d.RemovedPaths[0] != "/w/a.txt" {
		t.Fatalf("RemovedPaths = %v, want [/w/a.txt]", d.RemovedPaths)
	}
}

func TestDiffIgnoresArgvNoiseSameComm(t *testing.T) {
	baseline := []session.Event{{Kind: session.KindExec, Comm: "python3", Argv: []string{"python3", "-c", "print(1)"}}}
	candidate := []session.Event{{Kind: session.KindExec, Comm: "python3", Argv: []string{"python3", "-c", "print(2)"}}}
	d := Diff(baseline, candidate)
	if d.HasNewSurface() {
		t.Fatalf("same comm with different argv should not count as new surface: %+v", d)
	}
}

func TestDiffFallsBackToExeWhenCommEmpty(t *testing.T) {
	baseline := []session.Event{{Kind: session.KindExec, Exe: "/usr/bin/bash"}}
	candidate := []session.Event{{Kind: session.KindExec, Exe: "/usr/bin/curl"}}
	d := Diff(baseline, candidate)
	if len(d.NewExecs) != 1 || d.NewExecs[0] != "/usr/bin/curl" {
		t.Fatalf("NewExecs = %v, want [/usr/bin/curl]", d.NewExecs)
	}
}

func TestDiffTextRendersAdditionsAndVerdict(t *testing.T) {
	baseline := []session.Event{execEv("bash")}
	candidate := []session.Event{execEv("bash"), execEv("curl")}
	d := Diff(baseline, candidate)
	text := DiffText(d, "base.jsonl", "cand.jsonl")
	for _, want := range []string{
		"baseline:  base.jsonl",
		"candidate: cand.jsonl",
		"+ curl",
		"verdict:   candidate reaches new surface",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("diff text missing %q:\n%s", want, text)
		}
	}
}

func TestDiffTextNoChangeVerdict(t *testing.T) {
	s := sampleSession()
	text := DiffText(Diff(s, s), "a.jsonl", "b.jsonl")
	if !strings.Contains(text, "verdict:   candidate stayed within the baseline's surface") {
		t.Fatalf("expected no-new-surface verdict:\n%s", text)
	}
	if !strings.Contains(text, "execs: no change") {
		t.Fatalf("expected 'no change' for execs:\n%s", text)
	}
}
