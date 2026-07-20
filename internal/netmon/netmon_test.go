package netmon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseAddrV4(t *testing.T) {
	ip, port, err := ParseAddr("0100007F:1F90")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if ip.String() != "127.0.0.1" || port != 8080 {
		t.Fatalf("got %s:%d, want 127.0.0.1:8080", ip, port)
	}
	ip, port, err = ParseAddr("00000000:0000")
	if err != nil {
		t.Fatalf("ParseAddr zero: %v", err)
	}
	if !ip.IsUnspecified() || port != 0 {
		t.Fatalf("zero address parsed as %s:%d", ip, port)
	}
}

func TestParseAddrV6(t *testing.T) {
	ip, port, err := ParseAddr("00000000000000000000000001000000:0050")
	if err != nil {
		t.Fatalf("ParseAddr v6: %v", err)
	}
	if ip.String() != "::1" || port != 80 {
		t.Fatalf("got %s port %d, want ::1 port 80", ip, port)
	}
}

func TestParseAddrBad(t *testing.T) {
	for _, s := range []string{"", "nope", "GG00007F:0001", "0100007F", "abc:1:2"} {
		if _, _, err := ParseAddr(s); err == nil {
			t.Fatalf("ParseAddr(%q) should fail", s)
		}
	}
}

const sampleEstablished = "   1: 0100007F:0016 0200007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 ffff888003a0b100 20 4 30 10 -1"
const sampleListen = "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 7777 1 ffff888003a0b200 100 0 0 10 0"
const sampleHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

func TestParseLine(t *testing.T) {
	e, ok := ParseLine(sampleEstablished)
	if !ok {
		t.Fatal("ParseLine rejected a valid line")
	}
	if e.LAddr != "127.0.0.1:22" || e.RAddr != "127.0.0.2:50000" {
		t.Fatalf("addresses wrong: %+v", e)
	}
	if e.State != StateEstablished || e.Inode != 4242 || e.Family != 4 || e.RemoteZero {
		t.Fatalf("fields wrong: %+v", e)
	}

	if _, ok := ParseLine(sampleHeader); ok {
		t.Fatal("header line must be rejected")
	}

	e, ok = ParseLine(sampleListen)
	if !ok {
		t.Fatal("listen line should parse")
	}
	if e.State != StateListen || !e.RemoteZero {
		t.Fatalf("listen fields wrong: %+v", e)
	}
}

// fakeNet builds a procRoot where pid 55 owns the given socket inodes and
// the tcp table has the given contents.
func fakeNet(t *testing.T, tcp string, inodes []string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	fdDir := filepath.Join(root, "55", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(fdDir, "0")); err != nil {
		t.Fatal(err)
	}
	for i, ino := range inodes {
		name := filepath.Join(fdDir, strconv.Itoa(3+i))
		if err := os.Symlink("socket:["+ino+"]", name); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSocketInodes(t *testing.T) {
	root := fakeNet(t, "", []string{"4242", "9999"})
	inodes := SocketInodes(root, []int{55, 777})
	if len(inodes) != 2 || inodes[4242] != 55 || inodes[9999] != 55 {
		t.Fatalf("SocketInodes = %v", inodes)
	}
}

func TestPollerEmitsOncePerConnection(t *testing.T) {
	table := sampleHeader + "\n" + sampleEstablished + "\n" + sampleListen + "\n"
	root := fakeNet(t, table, []string{"4242", "7777"})
	p := NewPoller(root, func() []int { return []int{55} })

	evs := p.Poll()
	if len(evs) != 1 {
		t.Fatalf("want exactly 1 event (listener excluded), got %+v", evs)
	}
	ev := evs[0]
	if ev.RAddr != "127.0.0.2:50000" || ev.Proto != "tcp" || ev.PID != 55 || ev.Family != 4 {
		t.Fatalf("event wrong: %+v", ev)
	}
	if ev.Kind != "net" {
		t.Fatalf("kind = %q", ev.Kind)
	}

	// Dedupe: same connection must not be reported twice.
	if evs := p.Poll(); len(evs) != 0 {
		t.Fatalf("dedupe failed: %+v", evs)
	}
}

func TestPollerIgnoresUnownedSockets(t *testing.T) {
	table := sampleEstablished + "\n"
	root := fakeNet(t, table, []string{"1111"}) // owns a different inode
	p := NewPoller(root, func() []int { return []int{55} })
	if evs := p.Poll(); len(evs) != 0 {
		t.Fatalf("unowned socket reported: %+v", evs)
	}
}

func TestPollerMissingTables(t *testing.T) {
	// Only tcp exists; tcp6/udp/udp6 absent must not error or panic.
	table := sampleEstablished + "\n"
	root := fakeNet(t, table, []string{"4242"})
	p := NewPoller(root, func() []int { return []int{55} })
	if evs := p.Poll(); len(evs) != 1 {
		t.Fatalf("want 1 event, got %+v", evs)
	}
}

func TestReadTableMissing(t *testing.T) {
	if _, err := ReadTable(t.TempDir(), "tcp"); err == nil {
		t.Fatal("missing table should error")
	}
}
