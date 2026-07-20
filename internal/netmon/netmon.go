// Package netmon observes network egress by polling the /proc/net tables
// and joining them against socket inodes owned by the tracked process tree.
// This is the unprivileged tier: connections shorter than one poll interval
// can be missed (an eBPF tier for exact capture is on the roadmap). Only
// connection metadata is observed; payloads are never seen.
package netmon

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

// TCP states from include/net/tcp_states.h.
const (
	StateEstablished = 1
	StateListen      = 10
)

// Entry is one row of a /proc/net/{tcp,udp}{,6} table.
type Entry struct {
	Proto      string
	Family     int
	LAddr      string
	RAddr      string
	State      int
	Inode      uint64
	RemoteZero bool
}

// parseHexAddr4 decodes the kernel's little-endian hex IPv4 form "0100007F".
func parseHexAddr4(h string) (net.IP, error) {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return nil, err
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), nil
}

// parseHexAddr6 decodes the kernel's 32-hex-digit IPv6 form: four 32-bit
// groups, each printed as a little-endian word.
func parseHexAddr6(h string) (net.IP, error) {
	if len(h) != 32 {
		return nil, fmt.Errorf("bad ipv6 hex length %d", len(h))
	}
	ip := make(net.IP, 0, 16)
	for g := 0; g < 4; g++ {
		v, err := strconv.ParseUint(h[g*8:g*8+8], 16, 32)
		if err != nil {
			return nil, err
		}
		ip = append(ip, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return ip, nil
}

// ParseAddr decodes the "HEXADDR:HEXPORT" form used by proc net tables.
func ParseAddr(s string) (net.IP, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	p64, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	var ip net.IP
	switch len(s[:i]) {
	case 8:
		ip, err = parseHexAddr4(s[:i])
	case 32:
		ip, err = parseHexAddr6(s[:i])
	default:
		err = fmt.Errorf("bad address %q", s)
	}
	if err != nil {
		return nil, 0, err
	}
	return ip, int(p64), nil
}

// ParseLine parses one non-header row of a proc net table.
func ParseLine(line string) (Entry, bool) {
	f := strings.Fields(line)
	if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
		return Entry{}, false
	}
	lip, lport, err := ParseAddr(f[1])
	if err != nil {
		return Entry{}, false
	}
	rip, rport, err := ParseAddr(f[2])
	if err != nil {
		return Entry{}, false
	}
	st, err := strconv.ParseUint(f[3], 16, 8)
	if err != nil {
		return Entry{}, false
	}
	inode, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil {
		return Entry{}, false
	}
	fam := 4
	if len(f[1]) > 13 { // 32 hex chars + ':' + 4-hex port
		fam = 6
	}
	return Entry{
		Family:     fam,
		LAddr:      net.JoinHostPort(lip.String(), strconv.Itoa(lport)),
		RAddr:      net.JoinHostPort(rip.String(), strconv.Itoa(rport)),
		State:      int(st),
		Inode:      inode,
		RemoteZero: rip.IsUnspecified() && rport == 0,
	}, true
}

// ReadTable parses procRoot/net/<name>, where name is one of "tcp", "tcp6",
// "udp", "udp6".
func ReadTable(procRoot, name string) ([]Entry, error) {
	f, err := os.Open(filepath.Join(procRoot, "net", name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	proto := strings.TrimSuffix(name, "6")
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if e, ok := ParseLine(sc.Text()); ok {
			e.Proto = proto
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// SocketInodes maps socket inode to owning pid for the given pids by reading
// /proc/<pid>/fd symlinks. Vanished processes and unreadable fds are skipped.
func SocketInodes(procRoot string, pids []int) map[uint64]int {
	out := map[uint64]int{}
	for _, pid := range pids {
		fdDir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
		ents, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			target, err := os.Readlink(filepath.Join(fdDir, ent.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			ino, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
			if err != nil {
				continue
			}
			out[ino] = pid
		}
	}
	return out
}

var tables = []string{"tcp", "tcp6", "udp", "udp6"}

// Poller emits one net event per unique (proto, inode, remote) observed on a
// socket owned by the tracked tree with a non-zero remote address. TCP
// listeners are excluded; every other TCP state counts, so SYN_SENT records
// an egress ATTEMPT even if the peer never answers. UDP sockets appear only
// once connect()ed (the tables carry no per-datagram information).
type Poller struct {
	procRoot string
	pids     func() []int
	seen     map[string]bool
}

// NewPoller builds a Poller; pids supplies the current tree membership.
func NewPoller(procRoot string, pids func() []int) *Poller {
	return &Poller{procRoot: procRoot, pids: pids, seen: map[string]bool{}}
}

// Poll runs one scan cycle.
func (p *Poller) Poll() []session.Event {
	inodes := SocketInodes(p.procRoot, p.pids())
	if len(inodes) == 0 {
		return nil
	}
	var evs []session.Event
	for _, tb := range tables {
		entries, err := ReadTable(p.procRoot, tb)
		if err != nil {
			continue // table may be absent (e.g. ipv6 disabled)
		}
		for _, e := range entries {
			pid, owned := inodes[e.Inode]
			if !owned || e.Inode == 0 || e.RemoteZero {
				continue
			}
			if e.Proto == "tcp" && e.State == StateListen {
				continue
			}
			key := e.Proto + "/" + strconv.FormatUint(e.Inode, 10) + "/" + e.RAddr
			if p.seen[key] {
				continue
			}
			p.seen[key] = true
			evs = append(evs, session.Event{
				Kind: session.KindNet, PID: pid, Proto: e.Proto, Family: e.Family,
				LAddr: e.LAddr, RAddr: e.RAddr, Sensor: "poll",
			})
		}
	}
	return evs
}
