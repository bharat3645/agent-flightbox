# agent-flightbox

[![CI](https://github.com/bharat3645/agent-flightbox/actions/workflows/ci.yml/badge.svg)](https://github.com/bharat3645/agent-flightbox/actions)

A flight recorder for AI agents. `flightbox record -- <agent command>` captures
what the process tree actually did - every process started, every file
touched, every network connection - into one JSONL session file, then renders
it as a static HTML timeline.

Agents get prompt-injected, tools misbehave, and "what did it actually do?"
is usually answered by scrolling chat logs. Scanners check inputs and
sandboxes limit blast radius; flightbox covers the third leg: ground-truth
behavioral evidence, recorded at the OS level, replayable after the fact.

```
flightbox record -o session.jsonl -watch . -- my-agent --task "fix the bug"
flightbox summary session.jsonl
flightbox report session.jsonl        # -> session.html, static, zero JS
```

Linux only. Single static binary, stdlib only, no dependencies.

## Quickstart

```
go install github.com/bharat3645/agent-flightbox/cmd/flightbox@latest

# or from a clone:
go build -o flightbox ./cmd/flightbox

flightbox check                        # what can the current privilege see?
flightbox record -- bash -c 'curl https://example.com > /tmp/page.html'
flightbox summary flightbox-*.jsonl
```

A session looks like this (real capture, paths shortened):

```json
{"v":1,"kind":"session_start","cmd":["bash","workload.sh"],"root_pid":15,"sensors":{"proc":"poll","fs":"inotify","net":"poll"},"degradations":[],"ts":"2026-07-18T05:47:30.603254Z"}
{"kind":"exec","pid":15,"ppid":14,"comm":"bash","argv":["bash","workload.sh"],"sensor":"spawn","ts":"2026-07-18T05:47:30.603511Z"}
{"kind":"fs","op":"create","path":"/work/hello.txt","sensor":"inotify","ts":"2026-07-18T05:47:30.605416Z"}
{"kind":"net","pid":23,"proto":"tcp","family":4,"laddr":"127.0.0.1:52204","raddr":"127.0.0.1:48509","sensor":"poll","ts":"2026-07-18T05:47:30.719154Z"}
{"kind":"exit","pid":23,"comm":"python3","sensor":"poll","ts":"2026-07-18T05:47:31.267161Z"}
{"kind":"child_exit","pid":15,"exit_code":7,"ts":"2026-07-18T05:47:31.489264Z"}
{"kind":"session_end","events":21,"dropped":0,"ts":"2026-07-18T05:47:31.524755Z"}
```

## How it observes

flightbox uses tiered sensors and always tells you which tier you got: the
session header records the active sensors and every degradation. A recording
never silently pretends to more coverage than it had.

| Sensor | Privileged tier (root) | Unprivileged tier | Gap in the unprivileged tier |
|---|---|---|---|
| Processes | netlink proc connector: exact fork/exec/exit events with exit codes, no sampling | /proc polling (default 25ms) | processes shorter than one interval can be missed; fork vs exec not distinguishable |
| Files | inotify (same) | inotify, recursive on `-watch` roots | events are path-scoped, not attributed to a pid; new-subdirectory watch has the usual inotify race |
| Network | /proc/net polling (same) | /proc/net + `/proc/<pid>/fd` join (default 50ms) | connections shorter than one interval can be missed; UDP only visible once connect()ed |

The recorder makes itself a child subreaper (`PR_SET_CHILD_SUBREAPER`), so
orphaned grandchildren stay in the observed tree instead of reparenting to
init, and their zombies remain observable until reaped.

```
                 +--------------------------------------+
   flightbox --> | child process tree (your agent)      |
     |           +--------------------------------------+
     |  fork/exec/exit        file ops           sockets
     |  netlink cn_proc       inotify            /proc/net + fd join
     |  (or /proc polling)      |                    |
     v                v         v                    v
   +--------------------------------------------------+
   | event channel -> single writer -> session.jsonl  |
   +--------------------------------------------------+
                         |
              flightbox summary / report
```

## Honest limitations

- The polling tier samples. A 3ms `curl` between two 50ms polls is invisible.
  Run as root for the netlink tier (exact process events), and see the eBPF
  roadmap below for exact egress.
- fs events carry no pid: inotify cannot attribute. If two children write the
  same file, the timeline shows the writes, not the writers.
- Network events are connection metadata (5-tuple-ish), not payloads, and
  unconnected UDP (sendto-style DNS) is not visible in /proc tables.
- pid reuse over a long session could confuse attribution; sessions are
  typically short and pids monotonic, but it is not impossible.
- An adversarial *root* child could evade any userspace observer; flightbox
  is a recorder, not a sandbox. Contain first (see
  [toolcage](https://github.com/bharat3645/toolcage)), record always.

## Session schema (v1)

One JSON object per line. `ts` is RFC 3339 UTC, stamped by the single
writer, so timestamps are non-decreasing in file order.

| kind | fields beyond `ts` | notes |
|---|---|---|
| `session_start` | `v`, `cmd`, `root_pid`, `hostname`, `os`, `arch`, `sensors`, `degradations` | first line; `sensors` records the tier per sensor |
| `exec` | `pid`, `ppid`, `comm`, `exe`, `argv`, `truncated`, `sensor` | `sensor: spawn` (exact, the recorded command itself), `netlink` (exact), or `poll` (observed) |
| `fork` | `pid`, `ppid` | netlink tier only |
| `exit` | `pid`, `comm`, `exit_code`, `sensor` | `exit_code` present on netlink/reap tiers; absent when polling |
| `fs` | `op`, `path`, `dir`, `sensor` | ops: create, modify, close_write, delete, move_from, move_to, attrib |
| `net` | `pid`, `proto`, `family`, `laddr`, `raddr` | one event per unique connection; SYN_SENT counts (attempts are egress) |
| `child_exit` | `pid`, `exit_code` | the direct child's wait status, shell conventions (128+signal) |
| `sensor_error` | `sensor`, `error` | honesty channel: overflows and sensor failures are recorded in-band |
| `session_end` | `events`, `dropped` | last line; `events` counts all lines, `dropped` counts channel overflow losses |

## Reports

`flightbox report session.jsonl` writes a single self-contained HTML file:
process timeline bars, network egress table, files-touched table, full event
log, and the raw JSON. No JavaScript, no external assets, renders under any
CSP. `flightbox summary` prints the same digest as text.

## Privacy stance

flightbox records behavioral metadata only: paths, argv, process names,
socket addresses. It never reads file contents, never captures payloads, and
never records environment variable values. Session files are created 0600.
The CI audit enforces the schema strictly - an event carrying an unexpected
key fails the build (privacy canary).

Note that argv and paths themselves can be sensitive; treat session files as
logs of that sensitivity class.

## Exit codes

`flightbox record` exits with the child's exit code (128+signal for signal
deaths); 125 means flightbox itself failed. `summary`/`report` exit 1 on bad
input, 2 on usage errors.

## Development

```
go test -race ./...          # unit + integration (record e2e runs unprivileged)
go build -o flightbox ./cmd/flightbox
bash ci/smoke.sh             # end-to-end against the real binary
FLIGHTBOX="python3 ci/mock_flightbox.py" bash ci/smoke.sh   # harness self-test
```

The smoke harness (driver + strict session auditor) is itself validated
against `ci/mock_flightbox.py`, an independent Python implementation of the
same semantics - so a smoke failure indicts the Go code, not the harness.
CI runs the poll tier unprivileged and the netlink tier under sudo.

## Roadmap

- eBPF backend: exact egress (kprobe/tracepoint on connect paths) and
  pid-attributed file events, closing the polling gaps without root-only
  netlink.
- Per-event kernel timestamps on the netlink tier.
- `flightbox diff` between sessions (did the new agent version touch more?).

## Related tools

Part of an agent-trust stack: [mcp-sentinel](https://github.com/bharat3645/mcp-sentinel)
(lockfile + rug-pull detection for MCP servers),
[mcp-gateway-lite](https://github.com/bharat3645/mcp-gateway-lite) (auditing
reverse proxy), [toolcage](https://github.com/bharat3645/toolcage)
(per-tool-call WASM sandbox),
[agent-rules-audit](https://github.com/bharat3645/agent-rules-audit)
(instruction-file poisoning scanner). flightbox is the black-box recorder of
the family.

## License

MIT
