package procconn

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func TestSubscribeShape(t *testing.T) {
	msg := Subscribe(7)
	if len(msg) != 40 {
		t.Fatalf("subscribe message length = %d, want 40", len(msg))
	}
	le := binary.LittleEndian
	if le.Uint32(msg[0:]) != 40 {
		t.Fatalf("nlmsg_len = %d", le.Uint32(msg[0:]))
	}
	if le.Uint16(msg[4:]) != syscall.NLMSG_DONE {
		t.Fatalf("nlmsg_type = %d", le.Uint16(msg[4:]))
	}
	if le.Uint32(msg[8:]) != 7 {
		t.Fatalf("nlmsg_seq = %d", le.Uint32(msg[8:]))
	}
	if le.Uint32(msg[16:]) != CnIdxProc || le.Uint32(msg[20:]) != CnValProc {
		t.Fatal("connector id wrong")
	}
	if le.Uint16(msg[32:]) != 4 {
		t.Fatalf("cn_msg len = %d", le.Uint16(msg[32:]))
	}
	if le.Uint32(msg[36:]) != 1 {
		t.Fatalf("op = %d, want PROC_CN_MCAST_LISTEN", le.Uint32(msg[36:]))
	}
}

// mkMsg builds one netlink message carrying a proc_event with the given
// union words (which live at data offset 16).
func mkMsg(idx, val, what uint32, union []uint32) []byte {
	le := binary.LittleEndian
	data := make([]byte, 16+len(union)*4)
	le.PutUint32(data[0:], what)
	// cpu @4 and timestamp @8..15 stay zero.
	for i, u := range union {
		le.PutUint32(data[16+i*4:], u)
	}
	payload := make([]byte, cnHdrLen+len(data))
	le.PutUint32(payload[0:], idx)
	le.PutUint32(payload[4:], val)
	copy(payload[cnHdrLen:], data)
	msg := make([]byte, nlHdrLen+len(payload))
	le.PutUint32(msg[0:], uint32(len(msg)))
	le.PutUint16(msg[4:], syscall.NLMSG_DONE)
	copy(msg[nlHdrLen:], payload)
	return msg
}

func TestParseExec(t *testing.T) {
	// exec union: process_pid, process_tgid.
	msg := mkMsg(CnIdxProc, CnValProc, WhatExec, []uint32{4242, 4243})
	evs := Parse(msg)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].What != WhatExec || evs[0].PID != 4243 {
		t.Fatalf("exec decoded wrong: %+v", evs[0])
	}
}

func TestParseFork(t *testing.T) {
	// fork union: parent_pid, parent_tgid, child_pid, child_tgid.
	msg := mkMsg(CnIdxProc, CnValProc, WhatFork, []uint32{10, 10, 11, 11})
	evs := Parse(msg)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].PID != 11 || evs[0].PPID != 10 {
		t.Fatalf("fork decoded wrong: %+v", evs[0])
	}
}

func TestParseExit(t *testing.T) {
	// exit union: process_pid, process_tgid, exit_code, exit_signal.
	msg := mkMsg(CnIdxProc, CnValProc, WhatExit, []uint32{99, 99, 256, 17})
	evs := Parse(msg)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].PID != 99 || evs[0].ExitCode != 256 {
		t.Fatalf("exit decoded wrong: %+v", evs[0])
	}
}

func TestParseMultipleMessages(t *testing.T) {
	a := mkMsg(CnIdxProc, CnValProc, WhatExec, []uint32{1, 2})
	b := mkMsg(CnIdxProc, CnValProc, WhatExit, []uint32{2, 2, 0, 0})
	evs := Parse(append(a, b...))
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2", len(evs))
	}
	if evs[0].What != WhatExec || evs[1].What != WhatExit {
		t.Fatalf("order wrong: %+v", evs)
	}
}

func TestParseSkipsForeignAndAcks(t *testing.T) {
	foreign := mkMsg(2, 9, WhatExec, []uint32{1, 2})
	ack := mkMsg(CnIdxProc, CnValProc, WhatNone, []uint32{0, 0})
	uid := mkMsg(CnIdxProc, CnValProc, 0x4, []uint32{5, 5, 0, 0})
	good := mkMsg(CnIdxProc, CnValProc, WhatExec, []uint32{7, 8})
	buf := append(append(append(foreign, ack...), uid...), good...)
	evs := Parse(buf)
	if len(evs) != 1 || evs[0].PID != 8 {
		t.Fatalf("filtering wrong: %+v", evs)
	}
}

func TestParseTruncatedSafe(t *testing.T) {
	msg := mkMsg(CnIdxProc, CnValProc, WhatExec, []uint32{1, 2})
	for cut := 0; cut < len(msg); cut++ {
		_ = Parse(msg[:cut]) // must not panic
	}
	// A message whose header claims more bytes than exist.
	bogus := make([]byte, 16)
	binary.LittleEndian.PutUint32(bogus[0:], 4096)
	if evs := Parse(bogus); len(evs) != 0 {
		t.Fatalf("bogus length produced events: %+v", evs)
	}
}
