#!/usr/bin/env python3
"""Audit a flightbox session JSONL file.

Validates the schema strictly (unknown keys fail: sensors must never grow
surprise fields) and checks caller expectations. Prints "AUDIT OK (N checks)"
on success, exits 1 with a reason on the first failure.
"""
import argparse
import json
import os
import stat
import sys

CHECKS = 0


def ok():
    global CHECKS
    CHECKS += 1


def fail(msg):
    print("AUDIT FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)


def parse_ts(s):
    # RFC3339 with up to nanosecond fractions and a Z suffix.
    if not isinstance(s, str) or not s.endswith("Z"):
        fail("bad timestamp %r" % (s,))
    body = s[:-1]
    frac = 0.0
    if "." in body:
        body, fracs = body.split(".", 1)
        if not fracs.isdigit():
            fail("bad timestamp fraction %r" % (s,))
        frac = float("0." + fracs)
    import datetime

    try:
        dt = datetime.datetime.strptime(body, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        fail("unparseable timestamp %r" % (s,))
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp() + frac


ALLOWED_KEYS = {
    "session_start": {"v", "kind", "ts", "cmd", "root_pid", "hostname", "os",
                      "arch", "sensors", "degradations"},
    "exec": {"kind", "ts", "pid", "ppid", "comm", "exe", "argv", "truncated",
             "sensor"},
    "fork": {"kind", "ts", "pid", "ppid", "sensor"},
    "exit": {"kind", "ts", "pid", "comm", "exit_code", "sensor"},
    "fs": {"kind", "ts", "op", "path", "dir", "sensor"},
    "net": {"kind", "ts", "pid", "proto", "family", "laddr", "raddr",
            "sensor"},
    "child_exit": {"kind", "ts", "pid", "exit_code"},
    "sensor_error": {"kind", "ts", "sensor", "error"},
    "session_end": {"kind", "ts", "events", "dropped"},
}

FS_OPS = {"create", "modify", "close_write", "delete", "move_from",
          "move_to", "attrib"}
EXEC_SENSORS = {"spawn", "poll", "netlink"}
EXIT_SENSORS = {"poll", "netlink", "reap"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session")
    ap.add_argument("--backend", help="expected proc sensor tier")
    ap.add_argument("--expect-degraded", action="append", default=[],
                    help="substring expected in some degradation entry")
    ap.add_argument("--forbid-degraded", action="store_true",
                    help="degradations list must be empty or absent")
    ap.add_argument("--expect-net", action="append", default=[],
                    help="remote addr expected among net events")
    ap.add_argument("--expect-exec", action="append", default=[],
                    help="substring expected in some exec argv")
    ap.add_argument("--expect-fs-path", action="append", default=[],
                    help="path expected among fs events")
    ap.add_argument("--expect-fs-delete", action="append", default=[],
                    help="path expected with a delete fs event")
    ap.add_argument("--forbid-fs-path", action="append", default=[],
                    help="path that must NOT appear among fs events")
    ap.add_argument("--min-exec-pids", type=int, default=0)
    ap.add_argument("--expect-child-exit", type=int, default=None)
    ap.add_argument("--expect-perm", default=None, help="e.g. 0600")
    ap.add_argument("--expect-fork", action="store_true",
                    help="require at least one fork event (netlink tier)")
    ap.add_argument("--expect-exit-code", action="store_true",
                    help="require at least one exit event carrying a code")
    ap.add_argument("--allow-dropped", action="store_true")
    args = ap.parse_args()

    if args.expect_perm is not None:
        mode = stat.S_IMODE(os.stat(args.session).st_mode)
        want = int(args.expect_perm, 8)
        if mode != want:
            fail("session file mode %o, want %o" % (mode, want))
        ok()

    events = []
    with open(args.session) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError as e:
                fail("line %d is not JSON: %s" % (n, e))
    if not events:
        fail("empty session")
    ok()

    # Structural checks.
    if events[0].get("kind") != "session_start":
        fail("first event is %r, want session_start" % events[0].get("kind"))
    if events[0].get("v") != 1:
        fail("schema version %r, want 1" % events[0].get("v"))
    ok()
    if events[-1].get("kind") != "session_end":
        fail("last event is %r, want session_end" % events[-1].get("kind"))
    ok()
    start, end = events[0], events[-1]

    if end.get("events") != len(events):
        fail("session_end.events=%r but file has %d lines"
             % (end.get("events"), len(events)))
    ok()
    if not args.allow_dropped and end.get("dropped", 0) != 0:
        fail("dropped=%r events" % end.get("dropped"))
    ok()

    sensors = start.get("sensors")
    if not isinstance(sensors, dict):
        fail("session_start.sensors missing")
    for k in ("proc", "fs", "net"):
        if k not in sensors:
            fail("sensors.%s missing" % k)
    ok()
    if not isinstance(start.get("cmd"), list) or not start["cmd"]:
        fail("session_start.cmd missing")
    if not isinstance(start.get("root_pid"), int) or start["root_pid"] <= 0:
        fail("session_start.root_pid missing")
    ok()

    # Per-event schema checks, strict keys, monotonic timestamps.
    prev = None
    for i, ev in enumerate(events):
        kind = ev.get("kind")
        if kind not in ALLOWED_KEYS:
            fail("event %d has unknown kind %r" % (i, kind))
        extra = set(ev) - ALLOWED_KEYS[kind]
        if extra:
            fail("event %d (%s) carries unexpected keys %s (privacy canary)"
                 % (i, kind, sorted(extra)))
        ts = parse_ts(ev.get("ts"))
        if prev is not None and ts < prev - 0.005:
            fail("timestamps regress at event %d" % i)
        prev = max(ts, prev) if prev is not None else ts
        if kind == "exec":
            if not isinstance(ev.get("pid"), int) or ev["pid"] <= 0:
                fail("exec event %d has no pid" % i)
            if ev.get("sensor") not in EXEC_SENSORS:
                fail("exec event %d has bad sensor %r" % (i, ev.get("sensor")))
        elif kind == "fork":
            if ev.get("pid", 0) <= 0 or ev.get("ppid", 0) <= 0:
                fail("fork event %d incomplete" % i)
        elif kind == "exit":
            if ev.get("pid", 0) <= 0 or ev.get("sensor") not in EXIT_SENSORS:
                fail("exit event %d incomplete" % i)
        elif kind == "fs":
            if ev.get("op") not in FS_OPS:
                fail("fs event %d has bad op %r" % (i, ev.get("op")))
            if not ev.get("path"):
                fail("fs event %d has no path" % i)
            if ev.get("sensor") != "inotify":
                fail("fs event %d has bad sensor" % i)
        elif kind == "net":
            if ev.get("proto") not in ("tcp", "udp"):
                fail("net event %d has bad proto" % i)
            if ev.get("family") not in (4, 6):
                fail("net event %d has bad family" % i)
            for fld in ("laddr", "raddr"):
                v = ev.get(fld)
                if not isinstance(v, str) or ":" not in v:
                    fail("net event %d has bad %s %r" % (i, fld, v))
            if ev.get("pid", 0) <= 0:
                fail("net event %d has no pid" % i)
    ok()

    # Expectations.
    if args.backend is not None:
        if sensors.get("proc") != args.backend:
            fail("proc sensor is %r, want %r" % (sensors.get("proc"),
                                                 args.backend))
        ok()
    degr = start.get("degradations") or []
    for want in args.expect_degraded:
        if not any(want in d for d in degr):
            fail("no degradation mentions %r (got %r)" % (want, degr))
        ok()
    if args.forbid_degraded and degr:
        fail("unexpected degradations: %r" % (degr,))
    if args.forbid_degraded:
        ok()

    nets = [ev for ev in events if ev.get("kind") == "net"]
    for want in args.expect_net:
        if not any(ev.get("raddr") == want for ev in nets):
            fail("no net event with raddr %r (got %r)"
                 % (want, [ev.get("raddr") for ev in nets]))
        ok()

    execs = [ev for ev in events if ev.get("kind") == "exec"]
    for want in args.expect_exec:
        joined = [" ".join(ev.get("argv") or []) for ev in execs]
        if not any(want in j for j in joined):
            fail("no exec argv contains %r (got %r)" % (want, joined))
        ok()
    if args.min_exec_pids:
        pids = {ev["pid"] for ev in execs}
        if len(pids) < args.min_exec_pids:
            fail("only %d distinct exec pids, want >= %d"
                 % (len(pids), args.min_exec_pids))
        ok()

    fsevs = [ev for ev in events if ev.get("kind") == "fs"]
    for want in args.expect_fs_path:
        if not any(ev.get("path") == want for ev in fsevs):
            fail("no fs event for path %r" % want)
        ok()
    for want in args.expect_fs_delete:
        if not any(ev.get("path") == want and ev.get("op") == "delete"
                   for ev in fsevs):
            fail("no delete fs event for path %r" % want)
        ok()
    for bad in args.forbid_fs_path:
        if any(ev.get("path") == bad for ev in fsevs):
            fail("forbidden path %r appeared in fs events" % bad)
        ok()

    if args.expect_child_exit is not None:
        ce = [ev for ev in events if ev.get("kind") == "child_exit"]
        if len(ce) != 1:
            fail("want exactly one child_exit, got %d" % len(ce))
        if ce[0].get("exit_code") != args.expect_child_exit:
            fail("child_exit code %r, want %d"
                 % (ce[0].get("exit_code"), args.expect_child_exit))
        ok()

    if args.expect_fork:
        if not any(ev.get("kind") == "fork" for ev in events):
            fail("no fork events (netlink tier should produce them)")
        ok()
    if args.expect_exit_code:
        if not any(ev.get("kind") == "exit" and
                   isinstance(ev.get("exit_code"), int) for ev in events):
            fail("no exit event carries an exit_code")
        ok()

    print("AUDIT OK (%d checks)" % CHECKS)


if __name__ == "__main__":
    main()
