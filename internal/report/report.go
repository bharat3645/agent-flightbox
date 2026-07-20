// Package report renders flightbox session files as a one-screen text
// summary or a self-contained static HTML timeline. The HTML uses no
// JavaScript and no external assets: bar geometry is computed here and
// emitted as inline styles, so reports render identically anywhere,
// including under strict Content-Security-Policy.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

type procInfo struct {
	PID       int
	Comm      string
	Argv      string
	Sensor    string
	First     time.Time
	Exit      time.Time
	HasExit   bool
	ExitCode  string
	FirstSeen int // event index, for stable ordering
}

type agg struct {
	Start        *session.Event
	End          *session.Event
	FirstTS      time.Time
	LastTS       time.Time
	Execs        int
	Forks        int
	Exits        int
	Procs        []*procInfo
	FSCount      int
	FSOps        map[string]int
	FSPaths      map[string]int
	Nets         []session.Event
	NetByProto   map[string]int
	ChildExit    *int
	SensorErrors []session.Event
	Dropped      int
	Total        int
}

func parseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func aggregate(events []session.Event) *agg {
	a := &agg{
		FSOps:      map[string]int{},
		FSPaths:    map[string]int{},
		NetByProto: map[string]int{},
	}
	procs := map[int]*procInfo{}
	for i := range events {
		ev := &events[i]
		ts := parseTS(ev.TS)
		if !ts.IsZero() {
			if a.FirstTS.IsZero() || ts.Before(a.FirstTS) {
				a.FirstTS = ts
			}
			if ts.After(a.LastTS) {
				a.LastTS = ts
			}
		}
		touch := func(pid int) *procInfo {
			p, ok := procs[pid]
			if !ok {
				p = &procInfo{PID: pid, First: ts, FirstSeen: i}
				procs[pid] = p
				a.Procs = append(a.Procs, p)
			}
			return p
		}
		switch ev.Kind {
		case session.KindSessionStart:
			a.Start = ev
		case session.KindSessionEnd:
			a.End = ev
			a.Dropped = ev.Dropped
		case session.KindExec:
			a.Execs++
			p := touch(ev.PID)
			if ev.Comm != "" {
				p.Comm = ev.Comm
			}
			if len(ev.Argv) > 0 && p.Argv == "" {
				p.Argv = strings.Join(ev.Argv, " ")
			}
			if p.Sensor == "" {
				p.Sensor = ev.Sensor
			}
		case session.KindFork:
			a.Forks++
			touch(ev.PID)
		case session.KindExit:
			a.Exits++
			p := touch(ev.PID)
			p.Exit = ts
			p.HasExit = true
			if ev.ExitCode != nil {
				p.ExitCode = fmt.Sprintf("%d", *ev.ExitCode)
			} else {
				p.ExitCode = "?"
			}
		case session.KindChildExit:
			if ev.ExitCode != nil {
				c := *ev.ExitCode
				a.ChildExit = &c
			}
		case session.KindFS:
			a.FSCount++
			a.FSOps[ev.Op]++
			a.FSPaths[ev.Path]++
		case session.KindNet:
			a.Nets = append(a.Nets, *ev)
			a.NetByProto[ev.Proto]++
		case session.KindSensorError:
			a.SensorErrors = append(a.SensorErrors, *ev)
		}
	}
	a.Total = len(events)
	sort.SliceStable(a.Procs, func(i, j int) bool { return a.Procs[i].FirstSeen < a.Procs[j].FirstSeen })
	return a
}

func (a *agg) duration() time.Duration {
	if a.FirstTS.IsZero() || a.LastTS.IsZero() {
		return 0
	}
	return a.LastTS.Sub(a.FirstTS)
}

func (a *agg) backendLine() string {
	if a.Start == nil || len(a.Start.Sensors) == 0 {
		return "unknown"
	}
	keys := make([]string, 0, len(a.Start.Sensors))
	for k := range a.Start.Sensors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+a.Start.Sensors[k])
	}
	return strings.Join(parts, " ")
}

// Summary renders the one-screen text digest.
func Summary(events []session.Event) string {
	a := aggregate(events)
	var b strings.Builder
	fmt.Fprintf(&b, "flightbox session summary\n")
	if a.Start != nil {
		fmt.Fprintf(&b, "  cmd:        %s\n", strings.Join(a.Start.Cmd, " "))
		fmt.Fprintf(&b, "  started:    %s\n", a.Start.TS)
	}
	fmt.Fprintf(&b, "  duration:   %s\n", a.duration().Round(time.Millisecond))
	fmt.Fprintf(&b, "  backend:    %s\n", a.backendLine())
	if a.Start != nil && len(a.Start.Degradations) > 0 {
		for _, d := range a.Start.Degradations {
			fmt.Fprintf(&b, "  degraded:   %s\n", d)
		}
	} else {
		fmt.Fprintf(&b, "  degraded:   none\n")
	}
	fmt.Fprintf(&b, "  processes:  %d observed (%d exec, %d fork, %d exit)\n",
		len(a.Procs), a.Execs, a.Forks, a.Exits)
	ops := make([]string, 0, len(a.FSOps))
	for op := range a.FSOps {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	opParts := make([]string, 0, len(ops))
	for _, op := range ops {
		opParts = append(opParts, fmt.Sprintf("%s %d", op, a.FSOps[op]))
	}
	fmt.Fprintf(&b, "  files:      %d events across %d paths", a.FSCount, len(a.FSPaths))
	if len(opParts) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(opParts, ", "))
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "  network:    %d connections (tcp %d, udp %d)\n",
		len(a.Nets), a.NetByProto["tcp"], a.NetByProto["udp"])
	for _, n := range a.Nets {
		fmt.Fprintf(&b, "    %s %s (pid %d)\n", n.Proto, n.RAddr, n.PID)
	}
	if a.ChildExit != nil {
		fmt.Fprintf(&b, "  child exit: %d\n", *a.ChildExit)
	}
	for _, se := range a.SensorErrors {
		fmt.Fprintf(&b, "  sensor err: [%s] %s\n", se.Sensor, se.Error)
	}
	end := "session_end missing (recording interrupted?)"
	if a.End != nil {
		end = fmt.Sprintf("%d written, %d dropped", a.End.Events, a.Dropped)
	}
	fmt.Fprintf(&b, "  events:     %s\n", end)
	return b.String()
}

// Rows for the HTML template.

type procRow struct {
	PID      int
	Label    string
	Detail   string
	Left     float64
	Width    float64
	Open     bool // still running at session end
	ExitCode string
}

type netRow struct {
	TS     string
	Proto  string
	RAddr  string
	LAddr  string
	PID    int
	Family int
}

type fileRow struct {
	Path  string
	Count int
}

type htmlData struct {
	Title        string
	Cmd          string
	Started      string
	Duration     string
	Backend      string
	Degradations []string
	ProcCount    int
	FSCount      int
	NetCount     int
	ChildExit    string
	Procs        []procRow
	Nets         []netRow
	Files        []fileRow
	SensorErrors []string
	Lines        []string
	RawJSON      string
	Version      string
	Generated    string
}

// HTML renders the static timeline report.
func HTML(events []session.Event, version string) ([]byte, error) {
	a := aggregate(events)
	d := htmlData{
		Title:     "flightbox session",
		Duration:  a.duration().Round(time.Millisecond).String(),
		Backend:   a.backendLine(),
		ProcCount: len(a.Procs),
		FSCount:   a.FSCount,
		NetCount:  len(a.Nets),
		ChildExit: "?",
		Version:   version,
		Generated: session.Now(),
	}
	if a.Start != nil {
		d.Cmd = strings.Join(a.Start.Cmd, " ")
		d.Started = a.Start.TS
		d.Degradations = a.Start.Degradations
	}
	if a.ChildExit != nil {
		d.ChildExit = fmt.Sprintf("%d", *a.ChildExit)
	}
	span := a.LastTS.Sub(a.FirstTS)
	for _, p := range a.Procs {
		row := procRow{PID: p.PID, ExitCode: p.ExitCode}
		row.Label = p.Comm
		if row.Label == "" {
			row.Label = fmt.Sprintf("pid %d", p.PID)
		}
		row.Detail = p.Argv
		if span > 0 && !p.First.IsZero() {
			row.Left = float64(p.First.Sub(a.FirstTS)) / float64(span) * 100
			endT := a.LastTS
			if p.HasExit && !p.Exit.IsZero() {
				endT = p.Exit
			} else {
				row.Open = true
			}
			row.Width = float64(endT.Sub(p.First)) / float64(span) * 100
			if row.Width < 0.8 {
				row.Width = 0.8 // keep hairline processes visible
			}
			if row.Left+row.Width > 100 {
				row.Width = 100 - row.Left
			}
		} else {
			row.Width = 100
			row.Open = !p.HasExit
		}
		d.Procs = append(d.Procs, row)
	}
	for _, n := range a.Nets {
		d.Nets = append(d.Nets, netRow{TS: n.TS, Proto: n.Proto, RAddr: n.RAddr, LAddr: n.LAddr, PID: n.PID, Family: n.Family})
	}
	paths := make([]string, 0, len(a.FSPaths))
	for p := range a.FSPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		d.Files = append(d.Files, fileRow{Path: p, Count: a.FSPaths[p]})
	}
	for _, se := range a.SensorErrors {
		d.SensorErrors = append(d.SensorErrors, "["+se.Sensor+"] "+se.Error)
	}
	for _, ev := range events {
		d.Lines = append(d.Lines, eventLine(ev))
	}
	raw, err := json.MarshalIndent(events, "", " ")
	if err != nil {
		return nil, err
	}
	d.RawJSON = string(raw)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// eventLine renders one event as a compact human-readable log line.
func eventLine(ev session.Event) string {
	ts := ev.TS
	if t := parseTS(ev.TS); !t.IsZero() {
		ts = t.Format("15:04:05.000")
	}
	switch ev.Kind {
	case session.KindSessionStart:
		return fmt.Sprintf("%s  start  cmd=%q sensors=%v", ts, strings.Join(ev.Cmd, " "), ev.Sensors)
	case session.KindExec:
		return fmt.Sprintf("%s  exec   pid=%d %s [%s]", ts, ev.PID, strings.Join(ev.Argv, " "), ev.Sensor)
	case session.KindFork:
		return fmt.Sprintf("%s  fork   pid=%d ppid=%d", ts, ev.PID, ev.PPID)
	case session.KindExit:
		code := "?"
		if ev.ExitCode != nil {
			code = fmt.Sprintf("%d", *ev.ExitCode)
		}
		return fmt.Sprintf("%s  exit   pid=%d code=%s [%s]", ts, ev.PID, code, ev.Sensor)
	case session.KindFS:
		return fmt.Sprintf("%s  fs     %s %s", ts, ev.Op, ev.Path)
	case session.KindNet:
		return fmt.Sprintf("%s  net    %s -> %s (pid %d)", ts, ev.Proto, ev.RAddr, ev.PID)
	case session.KindChildExit:
		code := "?"
		if ev.ExitCode != nil {
			code = fmt.Sprintf("%d", *ev.ExitCode)
		}
		return fmt.Sprintf("%s  child  exit code=%s", ts, code)
	case session.KindSensorError:
		return fmt.Sprintf("%s  error  [%s] %s", ts, ev.Sensor, ev.Error)
	case session.KindSessionEnd:
		return fmt.Sprintf("%s  end    events=%d dropped=%d", ts, ev.Events, ev.Dropped)
	}
	return fmt.Sprintf("%s  %s", ts, ev.Kind)
}

var tmpl = template.Must(template.New("report").Parse(htmlTemplate))

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; background: #101418; color: #d6dde4;
  font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
h1 { font-size: 18px; margin: 0 0 4px; color: #e8eef4; }
h2 { font-size: 14px; margin: 28px 0 8px; color: #9fb4c8;
  text-transform: uppercase; letter-spacing: .08em; }
.meta { color: #8496a8; margin-bottom: 4px; }
.meta b { color: #c8d4e0; font-weight: 600; }
.warn { color: #e0b060; }
.err { color: #e07070; }
.stats { margin: 14px 0 0; display: flex; gap: 24px; flex-wrap: wrap; }
.stat .n { font-size: 22px; color: #e8eef4; }
.stat .l { color: #8496a8; font-size: 12px; }
.lane { display: grid; grid-template-columns: 220px 1fr 60px; gap: 8px;
  align-items: center; padding: 3px 0; border-bottom: 1px solid #1c232b; }
.lane .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.lane .name small { color: #68788a; }
.track { position: relative; height: 14px; background: #161c23; border-radius: 3px; }
.bar { position: absolute; top: 2px; height: 10px; border-radius: 2px;
  background: #3d7bb8; min-width: 2px; }
.bar.open { background: #b8873d; }
.code { text-align: right; color: #8496a8; }
table { border-collapse: collapse; width: 100%; }
td, th { text-align: left; padding: 3px 12px 3px 0; border-bottom: 1px solid #1c232b;
  vertical-align: top; }
th { color: #68788a; font-weight: 600; }
details { margin-top: 10px; }
summary { cursor: pointer; color: #9fb4c8; }
pre { background: #0b0e12; padding: 12px; border-radius: 6px; overflow-x: auto;
  font-size: 12px; }
.foot { margin-top: 32px; color: #4e5c6a; font-size: 12px; }
.detail { color: #68788a; overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; max-width: 60ch; }
</style>
</head>
<body>
<h1>flightbox session report</h1>
<div class="meta"><b>cmd:</b> {{.Cmd}}</div>
<div class="meta"><b>started:</b> {{.Started}} &middot; <b>duration:</b> {{.Duration}}
 &middot; <b>backend:</b> {{.Backend}} &middot; <b>child exit:</b> {{.ChildExit}}</div>
{{range .Degradations}}<div class="meta warn">degraded: {{.}}</div>{{end}}
{{range .SensorErrors}}<div class="meta err">sensor error: {{.}}</div>{{end}}

<div class="stats">
<div class="stat"><div class="n">{{.ProcCount}}</div><div class="l">processes</div></div>
<div class="stat"><div class="n">{{.FSCount}}</div><div class="l">file events</div></div>
<div class="stat"><div class="n">{{.NetCount}}</div><div class="l">connections</div></div>
</div>

<h2>Process timeline</h2>
{{range .Procs}}<div class="lane">
<div class="name">{{.Label}} <small>pid {{.PID}}</small>{{if .Detail}}<br><span class="detail">{{.Detail}}</span>{{end}}</div>
<div class="track"><div class="bar{{if .Open}} open{{end}}" style="left:{{printf "%.2f" .Left}}%;width:{{printf "%.2f" .Width}}%"></div></div>
<div class="code">{{if .Open}}&rarr;{{else}}{{.ExitCode}}{{end}}</div>
</div>{{end}}

<h2>Network egress</h2>
{{if .Nets}}<table>
<tr><th>time</th><th>proto</th><th>remote</th><th>local</th><th>pid</th></tr>
{{range .Nets}}<tr><td>{{.TS}}</td><td>{{.Proto}}{{if eq .Family 6}}6{{end}}</td><td>{{.RAddr}}</td><td>{{.LAddr}}</td><td>{{.PID}}</td></tr>{{end}}
</table>{{else}}<div class="meta">none observed</div>{{end}}

<h2>Files touched</h2>
{{if .Files}}<table>
<tr><th>path</th><th>events</th></tr>
{{range .Files}}<tr><td>{{.Path}}</td><td>{{.Count}}</td></tr>{{end}}
</table>{{else}}<div class="meta">none observed</div>{{end}}

<h2>Event log</h2>
<details open><summary>{{len .Lines}} events</summary>
<pre>{{range .Lines}}{{.}}
{{end}}</pre></details>

<details><summary>Raw session JSON</summary>
<pre>{{.RawJSON}}</pre></details>

<div class="foot">generated by flightbox {{.Version}} at {{.Generated}} &middot;
static report: no scripts, no external assets</div>
</body>
</html>
`
