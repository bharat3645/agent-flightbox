#!/usr/bin/env bash
# flightbox end-to-end smoke driver.
#
#   FLIGHTBOX=./flightbox bash ci/smoke.sh
#   FLIGHTBOX="python3 ci/mock_flightbox.py" bash ci/smoke.sh   # harness self-test
#
# Runs a real workload under the recorder (unprivileged poll tier, plus the
# netlink tier under sudo when available), audits every session with
# ci/check_session.py, and exercises summary/report/check/error paths.
# Prints "DRIVER OK (N checks)" then "SMOKE OK" on success.
set -u

FLIGHTBOX=${FLIGHTBOX:-./flightbox}
PY=${PY:-python3}
CHECKS=0

fail() {
    echo "SMOKE FAIL: $*" >&2
    exit 1
}
check() {
    CHECKS=$((CHECKS + 1))
}

TMP=$(mktemp -d)
SINK_PID=""
cleanup() {
    [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo rm -rf "$TMP"
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

# --- TCP sink -------------------------------------------------------------
PORTFILE="$TMP/port"
"$PY" - "$PORTFILE" <<'EOF' &
import socket, sys, threading
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(8)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.getsockname()[1]))
def drain(c):
    try:
        while c.recv(4096):
            pass
    except OSError:
        pass
    c.close()
while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=drain, args=(c,), daemon=True).start()
EOF
SINK_PID=$!
for _ in $(seq 1 100); do
    [ -s "$PORTFILE" ] && break
    sleep 0.05
done
[ -s "$PORTFILE" ] || fail "tcp sink did not start"
PORT=$(cat "$PORTFILE")
check

# --- 1. unprivileged recording (explicit poll backend) --------------------
WATCH="$TMP/w"
mkdir "$WATCH"
SESSION="$TMP/session.jsonl"
FB_EXIT=0
$FLIGHTBOX record -o "$SESSION" -watch "$WATCH" -backend poll \
    -proc-poll 15ms -net-poll 15ms -quiet \
    -- bash ci/workload.sh "$PORT" "$WATCH" || FB_EXIT=$?
[ "$FB_EXIT" -eq 7 ] || fail "record should propagate child exit 7, got $FB_EXIT"
check
[ -f "$SESSION" ] || fail "session file missing"
check

"$PY" ci/check_session.py "$SESSION" \
    --backend poll \
    --expect-net "127.0.0.1:$PORT" \
    --expect-exec "workload.sh" \
    --expect-exec "python3" \
    --expect-exec "sleep 0.2" \
    --expect-fs-path "$WATCH/hello.txt" \
    --expect-fs-delete "$WATCH/hello.txt" \
    --expect-fs-path "$WATCH/sub/inner.txt" \
    --forbid-fs-path "$SESSION" \
    --min-exec-pids 3 \
    --expect-child-exit 7 \
    --expect-perm 0600 || fail "poll-tier session audit failed"
check

# --- 2. auto backend degrades honestly without privilege ------------------
if [ "$(id -u)" -ne 0 ]; then
    SESSION_AUTO="$TMP/auto.jsonl"
    WATCH_AUTO="$TMP/wa"
    mkdir "$WATCH_AUTO"
    FB_EXIT=0
    $FLIGHTBOX record -o "$SESSION_AUTO" -watch "$WATCH_AUTO" -backend auto \
        -proc-poll 15ms -net-poll 15ms -quiet \
        -- bash -c "echo probe > \"$WATCH_AUTO/p.txt\"; sleep 0.1" || FB_EXIT=$?
    [ "$FB_EXIT" -eq 0 ] || fail "auto-backend record failed with $FB_EXIT"
    check
    "$PY" ci/check_session.py "$SESSION_AUTO" \
        --backend poll \
        --expect-degraded "netlink proc connector unavailable" \
        --expect-fs-path "$WATCH_AUTO/p.txt" \
        --expect-child-exit 0 || fail "degradation audit failed"
    check
fi

# --- 3. summary -----------------------------------------------------------
SUMMARY=$($FLIGHTBOX summary "$SESSION") || fail "summary exited nonzero"
echo "$SUMMARY" | grep -q "127.0.0.1:$PORT" || fail "summary misses the connection"
echo "$SUMMARY" | grep -q "child exit: 7" || fail "summary misses the child exit"
echo "$SUMMARY" | grep -q "backend:" || fail "summary misses the backend line"
check

# --- 4. report ------------------------------------------------------------
REPORT="$TMP/report.html"
$FLIGHTBOX report -o "$REPORT" "$SESSION" >/dev/null || fail "report exited nonzero"
[ -s "$REPORT" ] || fail "report file empty"
grep -q "flightbox session report" "$REPORT" || fail "report misses the header"
grep -q "127.0.0.1:$PORT" "$REPORT" || fail "report misses the connection"
if grep -q "<script" "$REPORT"; then fail "report must not contain scripts"; fi
check

# --- 5. check subcommand --------------------------------------------------
CHECK_OUT=$($FLIGHTBOX check) || fail "check exited nonzero"
echo "$CHECK_OUT" | grep -q "procfs:   ok" || fail "check misses procfs"
echo "$CHECK_OUT" | grep -q "inotify:  ok" || fail "check misses inotify"
check

# --- 6. error paths -------------------------------------------------------
$FLIGHTBOX record -quiet >/dev/null 2>&1
[ $? -eq 125 ] || fail "record without a command should exit 125"
check
$FLIGHTBOX summary "$TMP/does-not-exist.jsonl" >/dev/null 2>&1
[ $? -eq 1 ] || fail "summary of a missing file should exit 1"
check
$FLIGHTBOX frobnicate >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown subcommand should exit 2"
check
$FLIGHTBOX version | grep -q "flightbox" || fail "version output wrong"
check

# --- 7. netlink tier under sudo (exact fork/exec/exit) --------------------
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SESSION_NL="$TMP/netlink.jsonl"
    WATCH_NL="$TMP/wn"
    mkdir "$WATCH_NL"
    FB_EXIT=0
    sudo $FLIGHTBOX record -o "$SESSION_NL" -watch "$WATCH_NL" \
        -backend netlink -net-poll 15ms -quiet \
        -- bash ci/workload.sh "$PORT" "$WATCH_NL" || FB_EXIT=$?
    [ "$FB_EXIT" -eq 7 ] || fail "sudo record should propagate child exit 7, got $FB_EXIT"
    check
    sudo "$PY" ci/check_session.py "$SESSION_NL" \
        --backend netlink \
        --forbid-degraded \
        --expect-net "127.0.0.1:$PORT" \
        --expect-exec "workload.sh" \
        --expect-exec "python3" \
        --expect-fork \
        --expect-exit-code \
        --expect-fs-path "$WATCH_NL/hello.txt" \
        --expect-child-exit 7 \
        --expect-perm 0600 || fail "netlink-tier session audit failed"
    check
else
    echo "smoke: sudo unavailable, skipping netlink tier section"
fi

echo "DRIVER OK ($CHECKS checks)"
echo "SMOKE OK"
