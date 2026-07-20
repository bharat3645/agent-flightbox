// Package fsmon watches filesystem activity under chosen roots using
// inotify. Events are watched-path scoped and NOT attributed to a pid:
// inotify cannot say who touched a file (a fanotify/eBPF tier with pid
// attribution is on the roadmap). New subdirectories are watched as they
// appear, with the small creation race inherent to inotify. File contents
// are never read.
package fsmon

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/bharat3645/agent-flightbox/internal/session"
)

const watchMask = syscall.IN_CREATE | syscall.IN_MODIFY | syscall.IN_CLOSE_WRITE |
	syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_ATTRIB

// Watcher is a recursive inotify watcher.
type Watcher struct {
	fd      int
	epfd    int
	mu      sync.Mutex
	wdPath  map[int]string
	exclude map[string]bool
	done    chan struct{}
	once    sync.Once
	fdOnce  sync.Once
	started atomic.Bool
	wg      sync.WaitGroup
}

// New creates a watcher for the given root directories. Paths listed in
// exclude (matched absolute, exact) never produce events; flightbox uses
// this to keep its own session log out of the recording.
func New(roots []string, exclude []string) (*Watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &ev); err != nil {
		syscall.Close(fd)
		syscall.Close(epfd)
		return nil, fmt.Errorf("epoll_ctl: %w", err)
	}
	w := &Watcher{
		fd:      fd,
		epfd:    epfd,
		wdPath:  map[int]string{},
		exclude: map[string]bool{},
		done:    make(chan struct{}),
	}
	for _, p := range exclude {
		if abs, err := filepath.Abs(p); err == nil {
			w.exclude[abs] = true
		}
	}
	watched := 0
	for _, r := range roots {
		n, err := w.addRecursive(r)
		if err != nil {
			w.closeFDs()
			return nil, fmt.Errorf("watch %s: %w", r, err)
		}
		watched += n
	}
	if watched == 0 {
		w.closeFDs()
		return nil, fmt.Errorf("no watchable directories among %v", roots)
	}
	return w, nil
}

// addRecursive adds watches on root and every subdirectory, returning how
// many directories were watched. Unreadable subtrees are skipped silently.
func (w *Watcher) addRecursive(root string) (int, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return 0, err
	}
	n := 0
	walkErr := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // vanished or unreadable: skip
		}
		if !d.IsDir() {
			return nil
		}
		wd, werr := syscall.InotifyAddWatch(w.fd, path, watchMask)
		if werr != nil {
			return nil // permission denied etc: skip this dir
		}
		w.mu.Lock()
		w.wdPath[wd] = path
		w.mu.Unlock()
		n++
		return nil
	})
	return n, walkErr
}

// Run delivers events via emit until Close is called. It blocks; run it in
// a goroutine. Calling Run more than once is a no-op.
//
// wg.Add(1) happens before the CompareAndSwap on purpose: the atomic
// Store/Load pair on started only establishes a happens-before edge for
// code sequenced before the write propagating to code sequenced after the
// corresponding read. Close() observes started via w.started.Load() and
// then calls wg.Wait() - if Add(1) were sequenced after the CAS (as it
// was before this fix), Close() could reach Wait() on a zero-valued
// WaitGroup before this goroutine ever calls Add(1), which is a data race
// (and explicit WaitGroup misuse) that -race correctly flags. Adding
// before the CAS, with a compensating Done() on CAS failure, keeps Run()
// idempotent and keeps the Close()-without-Run() path (used by `flightbox
// check`) safe: started stays false there, so Close() never calls Wait().
func (w *Watcher) Run(emit func(session.Event)) {
	w.wg.Add(1)
	if !w.started.CompareAndSwap(false, true) {
		w.wg.Done()
		return
	}
	defer w.wg.Done()
	buf := make([]byte, 64*1024)
	epevs := make([]syscall.EpollEvent, 1)
	for {
		select {
		case <-w.done:
			return
		default:
		}
		n, err := syscall.EpollWait(w.epfd, epevs, 200)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return // epfd closed
		}
		if n == 0 {
			continue
		}
		for {
			m, rerr := syscall.Read(w.fd, buf)
			if m <= 0 || rerr != nil {
				break // EAGAIN: drained (or fd closed)
			}
			w.parse(buf[:m], emit)
		}
	}
}

func (w *Watcher) parse(b []byte, emit func(session.Event)) {
	// Fixed portion of struct inotify_event: wd(4) + mask(4) + cookie(4) +
	// len(4) = 16 bytes, followed by a name[len] byte array. Not exported
	// as a Sizeof constant by the standard syscall package, so it is
	// spelled out here rather than assumed.
	const hdr = 16
	off := 0
	for off+hdr <= len(b) {
		wd := int(int32(binary.LittleEndian.Uint32(b[off:])))
		mask := binary.LittleEndian.Uint32(b[off+4:])
		nameLen := int(binary.LittleEndian.Uint32(b[off+12:]))
		off += hdr
		if off+nameLen > len(b) {
			return
		}
		name := string(trimNul(b[off : off+nameLen]))
		off += nameLen
		if mask&syscall.IN_Q_OVERFLOW != 0 {
			emit(session.Event{
				Kind: session.KindSensorError, Sensor: "fs",
				Error: "inotify queue overflow: some fs events were lost",
			})
			continue
		}
		w.mu.Lock()
		dir := w.wdPath[wd]
		w.mu.Unlock()
		if dir == "" {
			continue
		}
		path := dir
		if name != "" {
			path = filepath.Join(dir, name)
		}
		if w.exclude[path] {
			continue
		}
		isDir := mask&syscall.IN_ISDIR != 0
		if isDir && mask&syscall.IN_CREATE != 0 {
			_, _ = w.addRecursive(path) // watch new directories as they appear
		}
		if op := opFor(mask); op != "" {
			emit(session.Event{Kind: session.KindFS, Op: op, Path: path, IsDir: isDir, Sensor: "inotify"})
		}
	}
}

func trimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// opFor maps an inotify mask to a flightbox op name.
func opFor(mask uint32) string {
	switch {
	case mask&syscall.IN_CREATE != 0:
		return "create"
	case mask&syscall.IN_CLOSE_WRITE != 0:
		return "close_write"
	case mask&syscall.IN_MODIFY != 0:
		return "modify"
	case mask&syscall.IN_DELETE != 0:
		return "delete"
	case mask&syscall.IN_MOVED_FROM != 0:
		return "move_from"
	case mask&syscall.IN_MOVED_TO != 0:
		return "move_to"
	case mask&syscall.IN_ATTRIB != 0:
		return "attrib"
	}
	return ""
}

// Close stops the run loop (if any) and releases the inotify and epoll fds.
// It is idempotent.
func (w *Watcher) Close() {
	w.once.Do(func() { close(w.done) })
	if w.started.Load() {
		w.wg.Wait()
	}
	w.closeFDs()
}

func (w *Watcher) closeFDs() {
	w.fdOnce.Do(func() {
		syscall.Close(w.fd)
		syscall.Close(w.epfd)
	})
}
