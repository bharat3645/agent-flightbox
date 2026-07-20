// Package procconn implements the Linux netlink process-events connector
// (CONFIG_PROC_EVENTS): exact fork, exec and exit notifications for the
// whole system, delivered by the kernel with no sampling gap. Receiving the
// multicast requires CAP_NET_ADMIN (typically root). The kernel accepts the
// subscription silently even without the capability and simply never
// delivers events, so callers must liveness-probe (see record.probeNetlink)
// rather than trust a successful Dial.
package procconn

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
)

// Linux constants (linux/netlink.h, linux/connector.h, linux/cn_proc.h).
const (
	netlinkConnector = 11

	CnIdxProc = 1
	CnValProc = 1

	procCnMcastListen = 1

	// proc_event.what values (subset flightbox decodes).
	WhatNone = 0x00000000
	WhatFork = 0x00000001
	WhatExec = 0x00000002
	WhatExit = 0x80000000
)

const (
	nlHdrLen = 16 // struct nlmsghdr
	cnHdrLen = 20 // struct cn_msg
)

// RawEvent is one decoded proc_event.
type RawEvent struct {
	What     uint32
	PID      int // process (exec/exit) or child (fork) tgid
	PPID     int // parent tgid, fork only
	ExitCode uint32
}

// Conn is an open netlink connector subscription.
type Conn struct {
	fd int
}

// Dial opens the netlink socket, binds to the proc-events multicast group
// and sends the PROC_CN_MCAST_LISTEN control message. A 200ms receive
// timeout is set so callers can poll for shutdown.
func Dial() (*Conn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, netlinkConnector)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_NETLINK, NETLINK_CONNECTOR): %w", err)
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: CnIdxProc}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := syscall.Sendto(fd, Subscribe(1), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	tv := syscall.Timeval{Sec: 0, Usec: 200000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("setsockopt(SO_RCVTIMEO): %w", err)
	}
	return &Conn{fd: fd}, nil
}

// Receive reads one datagram into buf and returns the decoded events. On
// timeout or interrupt it returns (nil, nil).
func (c *Conn) Receive(buf []byte) ([]RawEvent, error) {
	n, _, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			return nil, nil
		}
		return nil, err
	}
	return Parse(buf[:n]), nil
}

// Close releases the socket.
func (c *Conn) Close() {
	syscall.Close(c.fd)
}

// Subscribe builds the netlink+connector PROC_CN_MCAST_LISTEN message:
// nlmsghdr (len, type=NLMSG_DONE, flags, seq, pid), then cn_msg
// (id.idx, id.val, seq, ack, len, flags), then the 4-byte listen op.
func Subscribe(seq uint32) []byte {
	buf := make([]byte, nlHdrLen+cnHdrLen+4)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], uint32(len(buf)))
	le.PutUint16(buf[4:], syscall.NLMSG_DONE)
	le.PutUint16(buf[6:], 0)
	le.PutUint32(buf[8:], seq)
	le.PutUint32(buf[12:], uint32(os.Getpid()))
	le.PutUint32(buf[16:], CnIdxProc)
	le.PutUint32(buf[20:], CnValProc)
	le.PutUint32(buf[24:], seq)
	le.PutUint32(buf[28:], 0)
	le.PutUint16(buf[32:], 4)
	le.PutUint16(buf[34:], 0)
	le.PutUint32(buf[36:], procCnMcastListen)
	return buf
}

// Parse walks a datagram of netlink messages and extracts proc events.
// Malformed or foreign messages are skipped, never fatal.
func Parse(b []byte) []RawEvent {
	le := binary.LittleEndian
	var out []RawEvent
	off := 0
	for off+nlHdrLen <= len(b) {
		msgLen := int(le.Uint32(b[off:]))
		if msgLen < nlHdrLen || off+msgLen > len(b) {
			return out
		}
		if ev, ok := parseCn(b[off+nlHdrLen : off+msgLen]); ok {
			out = append(out, ev)
		}
		// Netlink messages are 4-byte aligned.
		if r := msgLen % 4; r != 0 {
			msgLen += 4 - r
		}
		off += msgLen
	}
	return out
}

// parseCn decodes one connector payload: cn_msg header then proc_event
// (what @0, cpu @4, timestamp @8, union @16).
func parseCn(p []byte) (RawEvent, bool) {
	le := binary.LittleEndian
	if len(p) < cnHdrLen+20 {
		return RawEvent{}, false
	}
	if le.Uint32(p[0:]) != CnIdxProc || le.Uint32(p[4:]) != CnValProc {
		return RawEvent{}, false
	}
	data := p[cnHdrLen:]
	ev := RawEvent{What: le.Uint32(data[0:])}
	switch ev.What {
	case WhatFork:
		if len(data) < 32 {
			return RawEvent{}, false
		}
		ev.PPID = int(int32(le.Uint32(data[20:]))) // parent tgid
		ev.PID = int(int32(le.Uint32(data[28:])))  // child tgid
	case WhatExec:
		if len(data) < 24 {
			return RawEvent{}, false
		}
		ev.PID = int(int32(le.Uint32(data[20:]))) // process tgid
	case WhatExit:
		if len(data) < 32 {
			return RawEvent{}, false
		}
		ev.PID = int(int32(le.Uint32(data[20:])))
		ev.ExitCode = le.Uint32(data[24:])
	default:
		return RawEvent{}, false
	}
	return ev, true
}
