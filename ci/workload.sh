#!/usr/bin/env bash
# Smoke workload: touches files, spawns a process tree, makes one TCP
# connection to the sink on 127.0.0.1:$1, then exits 7.
set -e
PORT=$1
WATCH=$2

echo hello > "$WATCH/hello.txt"
echo more >> "$WATCH/hello.txt"
mkdir "$WATCH/sub"
sleep 0.1
echo x > "$WATCH/sub/inner.txt"
rm "$WATCH/hello.txt"

python3 - "$PORT" <<'EOF'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
time.sleep(0.5)
s.close()
EOF

bash -c "sleep 0.2"
exit 7
