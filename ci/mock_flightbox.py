#!/usr/bin/env python3
"""Reference mock of the flightbox CLI, used to validate the smoke harness.

This is a deliberately independent Python implementation of the same
client-visible semantics: same subcommands, same flags, same JSONL schema,
same sensor tiers (netlink proc connector when privileged, /proc polling
otherwise, inotify fs watch, /proc/net egress join). If ci/smoke.sh +
ci/check_session.py pass against this mock, a failure against the real
binary indicts the Go implementation, not the harness. It also proves the
kernel-interface assumptions (stat parsing, inotify masks, proc-net hex
forms, cn_proc layout) on the machine that runs it.

Not a supported tool: use the Go binary.
"""
import ctypes
import html
import json
import os
import queue
import select
import signal
import socket
import stat as statmod
import struct
import subprocess
import sys
import threading
import time

VERSION = "0.1.0-mock"
ERR_EXIT = 125

# ---------------------------------------------------------------------------
# Event plumbing


def now_ts():
    t = time.time()
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))
    return "%s.%06dZ" % (base, int((t % 1) * 1e6))


class Session:
    def __init__(self, path):
        self.path = path
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        self.f = os.fdopen(fd, "w")
        self.q = queue.Queue(maxsize=4096)
        self.written = 0
        self.dropped = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._writer, daemon=True)

    def direct(self, ev):
        if "ts" not in ev:
            ev["ts"] = now_ts()
        with self.lock:
            self.f.write(json.dumps(ev) + "\n")
            self.written += 1

    def emit(self, ev):
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            self.dropped += 1

    def _writer(self):
        while not (self.stop.is_set() and self.q.empty()):
            try:
                ev = self.q.get(timeout=0.05)
            except queue.Empty:
                continue
            ev["ts"] = now_ts()
            self.direct(ev)

    def start(self):
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join()
        end = {"kind": "session_end", "events": self.written + 1,
               "dropped": self.dropped}
        self.direct(end)
        self.f.close()


# ---------------------------------------------------------------------------
# proc polling tier


def read_stat(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read().decode("ascii", "replace")
    except OSError:
        return None
    o = data.find("(")
    c = data.rfind(")")
    if o < 0 or c < 0 or c < o:
        return None
    rest = data[c + 1:].split()
    if len(rest) < 20:
        return None
    return {"pid": pid, "comm": data[o + 1:c], "state": rest[0],
            "ppid": int(rest[1])}


def read_cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            raw = f.read()
    except OSError:
        return []
    if not raw:
        return []
    return [a.decode("utf-8", "replace") for a in raw.rstrip(b"\0").split(b"\0")]


def list_pids():
    out = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            out.append(int(name))
    return out


class Tracker:
    def __init__(self, root_pid, adopter):
        self.members = {root_pid: {"exited": False, "comm": ""}}
        self.adopter = adopter
        self.lock = threading.Lock()

    def contains(self, pid):
        with self.lock:
            return pid in self.members

    def add(self, pid):
        with self.lock:
            if pid in self.members:
                return False
            self.members[pid] = {"exited": False, "comm": ""}
            return True

    def mark_exited(self, pid):
        with self.lock:
            m = self.members.get(pid)
            if m is None or m["exited"]:
                return False
            m["exited"] = True
            return True

    def active(self):
        with self.lock:
            return [p for p, m in self.members.items() if not m["exited"]]

    def poll(self, emit):
        snap = {}
        for pid in list_pids():
            st = read_stat(pid)
            if st:
                snap[pid] = st
        with self.lock:
            for pid, m in list(self.members.items()):
                if m["exited"]:
                    continue
                st = snap.get(pid)
                if st is None or st["state"] in ("Z", "X"):
                    m["exited"] = True
                    emit({"kind": "exit", "pid": pid, "comm": m["comm"],
                          "sensor": "poll"})
            for pid, st in snap.items():
                if pid in self.members:
                    if not self.members[pid]["comm"]:
                        self.members[pid]["comm"] = st["comm"]
                    continue
                if not self._reaches(pid, snap):
                    continue
                self.members[pid] = {"exited": False, "comm": st["comm"]}
                emit({"kind": "exec", "pid": pid, "ppid": st["ppid"],
                      "comm": st["comm"], "argv": read_cmdline(pid),
                      "sensor": "poll"})

    def _reaches(self, pid, snap):
        for _ in range(128):
            st = snap.get(pid)
            if st is None:
                return False
            if st["ppid"] in self.members or st["ppid"] == self.adopter:
                return True
            if st["ppid"] <= 1:
                return False
            pid = st["ppid"]
        return False


# ---------------------------------------------------------------------------
# network polling tier


def parse_hex_addr(h, port_hex):
    port = int(port_hex, 16)
    if len(h) == 8:
        ip = socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))
        return ip, port, 4, "%s:%d" % (ip, port)
    if len(h) == 32:
        raw = b"".join(struct.pack("<I", int(h[i:i + 8], 16))
                       for i in range(0, 32, 8))
        ip = socket.inet_ntop(socket.AF_INET6, raw)
        return ip, port, 6, "[%s]:%d" % (ip, port)
    raise ValueError(h)


class NetPoller:
    LISTEN = 0x0A

    def __init__(self, pids_fn):
        self.pids_fn = pids_fn
        self.seen = set()

    def socket_inodes(self):
        out = {}
        for pid in self.pids_fn():
            fd_dir = "/proc/%d/fd" % pid
            try:
                names = os.listdir(fd_dir)
            except OSError:
                continue
            for n in names:
                try:
                    target = os.readlink(os.path.join(fd_dir, n))
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    out[int(target[8:-1])] = pid
        return out

    def poll(self, emit):
        inodes = self.socket_inodes()
        if not inodes:
            return
        for name in ("tcp", "tcp6", "udp", "udp6"):
            try:
                with open("/proc/net/" + name) as f:
                    lines = f.readlines()
            except OSError:
                continue
            proto = name.rstrip("6")
            for line in lines:
                fields = line.split()
                if len(fields) < 10 or not fields[0].endswith(":"):
                    continue
                try:
                    lip, lport, fam, laddr = parse_hex_addr(
                        *fields[1].rsplit(":", 1))
                    rip, rport, _, raddr = parse_hex_addr(
                        *fields[2].rsplit(":", 1))
                    st = int(fields[3], 16)
                    inode = int(fields[9])
                except (ValueError, TypeError):
                    continue
                pid = inodes.get(inode)
                if pid is None or inode == 0:
                    continue
                remote_zero = rport == 0 and rip.strip("0:.") == ""
                if remote_zero:
                    continue
                if proto == "tcp" and st == self.LISTEN:
                    continue
                key = (proto, inode, raddr)
                if key in self.seen:
                    continue
                self.seen.add(key)
                emit({"kind": "net", "pid": pid, "proto": proto,
                      "family": fam, "laddr": laddr, "raddr": raddr,
                      "sensor": "poll"})


# ---------------------------------------------------------------------------
# inotify tier (ctypes)

IN_CREATE = 0x100
IN_MODIFY = 0x2
IN_CLOSE_WRITE = 0x8
IN_DELETE = 0x200
IN_MOVED_FROM = 0x40
IN_MOVED_TO = 0x80
IN_ATTRIB = 0x4
IN_ISDIR = 0x40000000
IN_Q_OVERFLOW = 0x4000
IN_NONBLOCK = 0x800
IN_CLOEXEC = 0x80000
WATCH_MASK = (IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE |
              IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB)


class FSWatcher:
    def __init__(self, roots, exclude):
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.fd = self.libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError("inotify_init1 failed")
        self.wd_path = {}
        self.exclude = {os.path.abspath(p) for p in exclude}
        self.stop = threading.Event()
        n = 0
        for r in roots:
            n += self.add_recursive(os.path.abspath(r))
        if n == 0:
            os.close(self.fd)
            raise OSError("no watchable directories among %r" % (roots,))

    def add_recursive(self, root):
        n = 0
        for dirpath, _, _ in os.walk(root):
            wd = self.libc.inotify_add_watch(
                self.fd, dirpath.encode(), WATCH_MASK)
            if wd >= 0:
                self.wd_path[wd] = dirpath
                n += 1
        return n

    def run(self, emit):
        while not self.stop.is_set():
            r, _, _ = select.select([self.fd], [], [], 0.2)
            if not r:
                continue
            try:
                buf = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                return
            off = 0
            while off + 16 <= len(buf):
                wd, mask, _cookie, length = struct.unpack_from("iIII", buf, off)
                off += 16
                name = buf[off:off + length].split(b"\0")[0].decode(
                    "utf-8", "replace")
                off += length
                if mask & IN_Q_OVERFLOW:
                    emit({"kind": "sensor_error", "sensor": "fs",
                          "error": "inotify queue overflow"})
                    continue
                d = self.wd_path.get(wd)
                if not d:
                    continue
                path = os.path.join(d, name) if name else d
                if path in self.exclude:
                    continue
                is_dir = bool(mask & IN_ISDIR)
                if is_dir and mask & IN_CREATE:
                    self.add_recursive(path)
                op = self.op_for(mask)
                if op:
                    ev = {"kind": "fs", "op": op, "path": path,
                          "sensor": "inotify"}
                    if is_dir:
                        ev["dir"] = True
                    emit(ev)

    @staticmethod
    def op_for(mask):
        for bit, op in ((IN_CREATE, "create"), (IN_CLOSE_WRITE, "close_write"),
                        (IN_MODIFY, "modify"), (IN_DELETE, "delete"),
                        (IN_MOVED_FROM, "move_from"), (IN_MOVED_TO, "move_to"),
                        (IN_ATTRIB, "attrib")):
            if mask & bit:
                return op
        return ""

    def close(self):
        self.stop.set()


# ---------------------------------------------------------------------------
# netlink proc connector tier

NETLINK_CONNECTOR = 11
PROC_EVENTS = {"fork": 0x1, "exec": 0x2, "exit": 0x80000000}


class Netlink:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                                  NETLINK_CONNECTOR)
        self.sock.bind((0, 1))
        sub = struct.pack("=IHHIIIIIIHHI", 40, 3, 0, 1, os.getpid(),
                          1, 1, 1, 0, 4, 0, 1)
        self.sock.sendto(sub, (0, 0))
        self.sock.settimeout(0.2)

    def receive(self):
        try:
            buf = self.sock.recv(262144)
        except socket.timeout:
            return []
        except OSError:
            return None
        out = []
        off = 0
        while off + 16 <= len(buf):
            (msg_len,) = struct.unpack_from("=I", buf, off)
            if msg_len < 16 or off + msg_len > len(buf):
                break
            payload = buf[off + 16:off + msg_len]
            ev = self.parse_cn(payload)
            if ev:
                out.append(ev)
            if msg_len % 4:
                msg_len += 4 - msg_len % 4
            off += msg_len
        return out

    @staticmethod
    def parse_cn(p):
        if len(p) < 40:
            return None
        idx, val = struct.unpack_from("=II", p, 0)
        if idx != 1 or val != 1:
            return None
        data = p[20:]
        (what,) = struct.unpack_from("=I", data, 0)
        if what == PROC_EVENTS["fork"]:
            _pp, ptgid, _cp, ctgid = struct.unpack_from("=IIII", data, 16)
            return {"what": "fork", "pid": ctgid, "ppid": ptgid}
        if what == PROC_EVENTS["exec"]:
            _p, tgid = struct.unpack_from("=II", data, 16)
            return {"what": "exec", "pid": tgid}
        if what == PROC_EVENTS["exit"]:
            _p, tgid, code, _sig = struct.unpack_from("=IIII", data, 16)
            return {"what": "exit", "pid": tgid, "code": code}
        return None

    def close(self):
        self.sock.close()


def probe_netlink():
    try:
        nl = Netlink()
    except OSError as e:
        return None, str(e)
    try:
        subprocess.run(["/bin/true"], check=False)
    except OSError:
        pass
    deadline = time.time() + 0.6
    while time.time() < deadline:
        evs = nl.receive()
        if evs is None:
            nl.close()
            return None, "receive failed"
        if evs:
            return nl, ""
    nl.close()
    return None, "subscribed but no events delivered (needs root)"


def decode_wait(code):
    if os.WIFEXITED(code):
        return os.WEXITSTATUS(code)
    if os.WIFSIGNALED(code):
        return 128 + os.WTERMSIG(code)
    return code


# ---------------------------------------------------------------------------
# subcommands


def parse_duration(s):
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("s"):
        return float(s[:-1])
    return float(s)


def cmd_record(args):
    out = ""
    watch = []
    backend = "auto"
    proc_poll = 0.025
    net_poll = 0.05
    no_fs = no_net = quiet = False
    argv = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            argv = args[i + 1:]
            break
        if a in ("-o", "--o"):
            out = args[i + 1]
            i += 2
        elif a in ("-watch", "--watch"):
            watch.append(args[i + 1])
            i += 2
        elif a in ("-backend", "--backend"):
            backend = args[i + 1]
            i += 2
        elif a in ("-proc-poll", "--proc-poll"):
            proc_poll = parse_duration(args[i + 1])
            i += 2
        elif a in ("-net-poll", "--net-poll"):
            net_poll = parse_duration(args[i + 1])
            i += 2
        elif a in ("-no-fs", "--no-fs"):
            no_fs = True
            i += 1
        elif a in ("-no-net", "--no-net"):
            no_net = True
            i += 1
        elif a in ("-quiet", "--quiet"):
            quiet = True
            i += 1
        else:
            argv = args[i:]
            break
    if not argv:
        print("flightbox record: no command given", file=sys.stderr)
        return ERR_EXIT
    if not out:
        out = "flightbox-%d.jsonl" % int(time.time())
    if not watch:
        watch = ["."]

    # Subreaper.
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.prctl(36, 1, 0, 0, 0)

    degradations = []
    sensors = {}
    nl = None
    if backend == "poll":
        sensors["proc"] = "poll"
    elif backend in ("auto", "netlink"):
        nl, reason = probe_netlink()
        if nl:
            sensors["proc"] = "netlink"
        elif backend == "netlink":
            print("flightbox record: --backend netlink requested but "
                  "unavailable: %s" % reason, file=sys.stderr)
            return ERR_EXIT
        else:
            sensors["proc"] = "poll"
            degradations.append(
                "netlink proc connector unavailable (%s): using /proc "
                "polling; processes shorter than one interval may be missed"
                % reason)
    else:
        print("flightbox record: unknown backend %r" % backend,
              file=sys.stderr)
        return ERR_EXIT

    sess = Session(out)
    watcher = None
    if no_fs:
        sensors["fs"] = "off"
    else:
        try:
            watcher = FSWatcher(watch, [out])
            sensors["fs"] = "inotify"
        except OSError as e:
            sensors["fs"] = "off"
            degradations.append("fs sensor disabled: %s" % e)
    sensors["net"] = "off" if no_net else "poll"

    child = subprocess.Popen(argv)
    tracker = Tracker(child.pid, os.getpid())

    sess.direct({"v": 1, "kind": "session_start", "cmd": argv,
                 "root_pid": child.pid, "hostname": socket.gethostname(),
                 "os": "linux", "arch": os.uname().machine,
                 "sensors": sensors, "degradations": degradations})
    sess.start()
    if not quiet:
        print("flightbox(mock): recording to %s" % out, file=sys.stderr)

    sess.emit({"kind": "exec", "pid": child.pid, "ppid": os.getpid(),
               "comm": os.path.basename(argv[0]), "exe": argv[0],
               "argv": argv, "sensor": "spawn"})

    stop = threading.Event()
    threads = []

    if watcher:
        t = threading.Thread(target=watcher.run, args=(sess.emit,),
                             daemon=True)
        t.start()
        threads.append(t)

    if nl:
        def nl_loop():
            while not stop.is_set():
                evs = nl.receive()
                if evs is None:
                    return
                for e in evs:
                    if e["what"] == "fork":
                        if tracker.contains(e["ppid"]) and tracker.add(e["pid"]):
                            sess.emit({"kind": "fork", "pid": e["pid"],
                                       "ppid": e["ppid"],
                                       "sensor": "netlink"})
                    elif e["what"] == "exec":
                        if tracker.contains(e["pid"]):
                            st = read_stat(e["pid"]) or {}
                            sess.emit({"kind": "exec", "pid": e["pid"],
                                       "comm": st.get("comm", ""),
                                       "argv": read_cmdline(e["pid"]),
                                       "sensor": "netlink"})
                    elif e["what"] == "exit":
                        if tracker.contains(e["pid"]) and \
                                tracker.mark_exited(e["pid"]):
                            sess.emit({"kind": "exit", "pid": e["pid"],
                                       "exit_code": decode_wait(e["code"]),
                                       "sensor": "netlink"})
        t = threading.Thread(target=nl_loop, daemon=True)
        t.start()
        threads.append(t)
    else:
        def poll_loop():
            while not stop.is_set():
                tracker.poll(sess.emit)
                time.sleep(proc_poll)
        t = threading.Thread(target=poll_loop, daemon=True)
        t.start()
        threads.append(t)

    poller = None
    if not no_net:
        poller = NetPoller(tracker.active)

        def net_loop():
            while not stop.is_set():
                poller.poll(sess.emit)
                time.sleep(net_poll)
        t = threading.Thread(target=net_loop, daemon=True)
        t.start()
        threads.append(t)

    code = child.wait()
    child_code = code if code >= 0 else 128 - code
    tracker.mark_exited(child.pid)

    time.sleep(max(net_poll, proc_poll) + 0.02)
    stop.set()
    if watcher:
        watcher.close()
    for t in threads:
        t.join(timeout=2)
    if nl:
        nl.close()

    if not nl:
        tracker.poll(sess.emit)
    if poller:
        poller.poll(sess.emit)

    # Reap orphans (we are a subreaper).
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid <= 0:
            break
        if tracker.contains(pid) and tracker.mark_exited(pid):
            sess.emit({"kind": "exit", "pid": pid,
                       "exit_code": decode_wait(status), "sensor": "reap"})

    sess.emit({"kind": "child_exit", "pid": child.pid,
               "exit_code": child_code})
    sess.finish()
    if not quiet:
        print("flightbox(mock): recorded to %s (child exit %d)"
              % (out, child_code), file=sys.stderr)
    return child_code


def load(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def cmd_summary(args):
    if len(args) != 1:
        print("usage: flightbox summary <session.jsonl>", file=sys.stderr)
        return 2
    try:
        events = load(args[0])
    except OSError as e:
        print("flightbox summary: %s" % e, file=sys.stderr)
        return 1
    start = events[0] if events else {}
    sensors = start.get("sensors", {})
    backend = " ".join("%s=%s" % (k, sensors[k]) for k in sorted(sensors))
    nets = [e for e in events if e.get("kind") == "net"]
    execs = [e for e in events if e.get("kind") == "exec"]
    forks = [e for e in events if e.get("kind") == "fork"]
    exits = [e for e in events if e.get("kind") == "exit"]
    fsevs = [e for e in events if e.get("kind") == "fs"]
    pids = {e["pid"] for e in execs + forks + exits if e.get("pid")}
    print("flightbox session summary (mock)")
    print("  cmd:        %s" % " ".join(start.get("cmd", [])))
    print("  backend:    %s" % backend)
    for d in start.get("degradations", []) or ["none"]:
        print("  degraded:   %s" % d)
    print("  processes:  %d observed (%d exec, %d fork, %d exit)"
          % (len(pids), len(execs), len(forks), len(exits)))
    print("  files:      %d events" % len(fsevs))
    tcp = sum(1 for n in nets if n.get("proto") == "tcp")
    udp = sum(1 for n in nets if n.get("proto") == "udp")
    print("  network:    %d connections (tcp %d, udp %d)"
          % (len(nets), tcp, udp))
    for n in nets:
        print("    %s %s (pid %d)" % (n.get("proto"), n.get("raddr"),
                                      n.get("pid", 0)))
    for e in events:
        if e.get("kind") == "child_exit":
            print("  child exit: %d" % e.get("exit_code", -1))
    for e in events:
        if e.get("kind") == "session_end":
            print("  events:     %d written, %d dropped"
                  % (e.get("events", 0), e.get("dropped", 0)))
    return 0


def cmd_report(args):
    out = ""
    rest = []
    i = 0
    while i < len(args):
        if args[i] in ("-o", "--o"):
            out = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if len(rest) != 1:
        print("usage: flightbox report [-o out.html] <session.jsonl>",
              file=sys.stderr)
        return 2
    try:
        events = load(rest[0])
    except OSError as e:
        print("flightbox report: %s" % e, file=sys.stderr)
        return 1
    if not out:
        out = rest[0].rsplit(".jsonl", 1)[0] + ".html"
    nets = [e for e in events if e.get("kind") == "net"]
    body = ["<!DOCTYPE html><html><head><meta charset=\"utf-8\">",
            "<title>flightbox session</title></head><body>",
            "<h1>flightbox session report (mock)</h1>"]
    for n in nets:
        body.append("<div>net %s</div>" % html.escape(str(n.get("raddr"))))
    for e in events:
        if e.get("kind") == "fs":
            body.append("<div>fs %s %s</div>"
                        % (html.escape(str(e.get("op"))),
                           html.escape(str(e.get("path")))))
    body.append("<footer>no scripts, no external assets</footer>")
    body.append("</body></html>")
    with open(out, "w") as f:
        f.write("\n".join(body))
    print("flightbox: report written to %s" % out)
    return 0


def cmd_check():
    print("flightbox %s sensor availability" % VERSION)
    print("  os:       linux ok")
    ok = read_stat(os.getpid()) is not None
    print("  procfs:   ok" if ok else "  procfs:   unavailable")
    try:
        open("/proc/net/tcp").close()
        print("  proc_net: ok")
    except OSError as e:
        print("  proc_net: unavailable (%s)" % e)
    try:
        w = FSWatcher(["/tmp"], [])
        w.close()
        print("  inotify:  ok")
    except OSError as e:
        print("  inotify:  unavailable (%s)" % e)
    nl, reason = probe_netlink()
    if nl:
        nl.close()
        print("  netlink:  ok (exact fork/exec/exit events)")
    else:
        print("  netlink:  unavailable (%s)" % reason)
    return 0


def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    args = sys.argv[1:]
    if not args:
        print("usage: flightbox <record|summary|report|check|version>",
              file=sys.stderr)
        return 2
    cmd = args[0]
    if cmd == "record":
        return cmd_record(args[1:])
    if cmd == "summary":
        return cmd_summary(args[1:])
    if cmd == "report":
        return cmd_report(args[1:])
    if cmd == "check":
        return cmd_check()
    if cmd in ("version", "-v", "--version"):
        print("flightbox %s" % VERSION)
        return 0
    print("flightbox: unknown command %r" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
