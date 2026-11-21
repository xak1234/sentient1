// Package service is the always-on SYSTEM service: it subscribes to bait
// access events, runs the response engine, and keeps baits healthy.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/baits"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/engine"
	"github.com/xak1234/sentient1/internal/evtlog"
	"github.com/xak1234/sentient1/internal/instant"
	"github.com/xak1234/sentient1/internal/logx"
	"github.com/xak1234/sentient1/internal/netguard"
	"github.com/xak1234/sentient1/internal/notify"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/procinfo"
	"github.com/xak1234/sentient1/internal/session"
	"github.com/xak1234/sentient1/internal/winsec"
)

// Custom service control codes (128-255).
const (
	ControlCheckNow = 128
)

var Version = "dev"

// Run runs as a Windows service, or in the foreground when console is true.
func Run(console bool) error {
	if console {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := newServer(true)
		return s.run(ctx, nil)
	}
	// A service has no console: without this, a crash (an unrecovered panic in
	// some goroutine, a fatal runtime error) leaves no trace at all.
	os.MkdirAll(paths.DataDir(), 0o755)
	if f, err := os.OpenFile(filepath.Join(paths.DataDir(), "crash.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		fmt.Fprintf(f, "--- service %s started %s (pid %d)\n", Version, time.Now().Format(time.RFC3339), os.Getpid())
		debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	return svc.Run(paths.ServiceName, &handler{})
}

type handler struct{}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newServer(false)
	done := make(chan error, 1)
	ctl := make(chan svc.Cmd, 4)
	go func() { done <- s.run(ctx, ctl) }()
	// Report "running" only once bait access is actually being watched, so
	// `sentient1 install` returns when protection is live, not before.
	select {
	case <-s.ready:
	case err := <-done:
		if err != nil {
			s.log.Printf("service failed to start: %v", err)
			return false, 1
		}
		return false, 0
	case <-time.After(25 * time.Second):
	}
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			case svc.ParamChange, ControlCheckNow:
				select {
				case ctl <- c.Cmd:
				default:
				}
			}
		case err := <-done:
			if err != nil {
				s.log.Printf("service stopped with error: %v", err)
				cancel()
				return false, 1 // non-zero exit -> SCM recovery restarts us
			}
			return false, 0
		}
	}
}

type server struct {
	log       *logx.Logger
	eng       *engine.Engine
	mu        sync.Mutex
	cfg       *config.Config
	secrets   *config.Secrets
	dial      *notify.DialCache
	cliExe    string
	selfExe   string
	sub       *evtlog.Subscription
	watch     *instant.Watcher
	listening chan struct{} // closed once the event-log subscription is live
	ready     chan struct{} // closed when the service is protecting (reported to Windows)
	once1     sync.Once
	once2     sync.Once
}

func newServer(echo bool) *server {
	os.MkdirAll(paths.DataDir(), 0o755)
	exe, _ := os.Executable()
	s := &server{log: logx.New(paths.LogFile(), echo), selfExe: exe, cliExe: filepath.Join(filepath.Dir(exe), paths.CLIExe),
		listening: make(chan struct{}), ready: make(chan struct{})}
	if _, err := os.Stat(s.cliExe); err != nil {
		s.cliExe = exe // dev builds: one binary
	}
	s.eng = engine.New(s, uint32(os.Getpid()))
	s.watch = &instant.Watcher{Self: uint32(os.Getpid()), OnOpen: s.onOpen, Suspect: s.eng.SweepSuspect, Logf: s.log.Printf}
	config.SlowLock = func(d time.Duration, caller string) {
		s.log.Printf("state lock held %v by %s", d.Round(time.Millisecond), caller)
	}
	return s
}

func (s *server) reload() error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	sec, err := config.LoadSecrets()
	if err != nil {
		s.log.Printf("secrets: %v", err)
		sec = &config.Secrets{}
	}
	st, err := config.LoadState()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg, s.secrets = cfg, sec
	if s.dial == nil {
		s.dial = notify.NewDialCache(st.DialCache)
	}
	s.mu.Unlock()
	s.eng.Configure(cfg, st)
	var guarded []string
	if cfg.InstantFreeze {
		for _, bs := range st.Baits {
			if bs.Status == "retired" {
				continue
			}
			for _, f := range bs.Files {
				if f.Audit {
					guarded = append(guarded, f.Path)
				}
			}
		}
	}
	s.watch.Sync(guarded)
	return nil
}

func (s *server) run(ctx context.Context, ctl <-chan svc.Cmd) error {
	s.log.Printf("SENTIENT1 service %s starting (pid %d)", Version, os.Getpid())
	if err := winsec.EnablePrivilege(winsec.SeDebugPrivilege); err != nil {
		s.log.Printf("SeDebugPrivilege: %v", err)
	}
	if err := s.reload(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	config.UpdateState(func(st *config.State) error {
		st.ServiceVersion = Version
		st.Heartbeat = time.Now()
		return nil
	})
	// Start listening for bait access BEFORE anything slow (the startup health
	// check takes seconds): otherwise reads right after a restart or reconfigure
	// were missed. The service only reports "running" once this is live.
	events := make(chan string, 1024)
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	go s.subscribeLoop(subCtx, events)
	select {
	case <-s.listening:
	case <-time.After(10 * time.Second):
		s.log.Printf("event log subscription not ready after 10 s; continuing")
	}
	s.markReady()
	s.safe("startup health check", func() { s.healthCheck(true) })

	// Per-PID workers: events from one process are handled in order (so they
	// aggregate into one alert) while different processes don't wait on each other.
	const workers = 8
	queues := make([]chan *evtlog.ObjectAccess, workers)
	for i := range queues {
		queues[i] = make(chan *evtlog.ObjectAccess, 256)
		go func(q chan *evtlog.ObjectAccess) {
			for oa := range q {
				func() {
					defer func() {
						if r := recover(); r != nil {
							s.log.Printf("PANIC handling event: %v\n%s", r, debug.Stack())
						}
					}()
					s.eng.HandleAccess(oa)
				}()
			}
		}(queues[i])
	}

	health := time.NewTicker(5 * time.Minute)
	beat := time.NewTicker(time.Minute)
	dialRefresh := time.NewTicker(30 * time.Minute)
	defer health.Stop()
	defer beat.Stop()
	defer dialRefresh.Stop()
	s.refreshDial(ctx)
	go s.updateLoop(ctx)

	for {
		select {
		case <-ctx.Done():
			s.saveBookmark()
			s.watch.Stop()
			s.log.Printf("service stopping")
			return nil
		case x := <-events:
			ev, err := evtlog.Parse(x)
			if err != nil {
				continue
			}
			oa, ok := ev.AsObjectAccess()
			if !ok {
				continue
			}
			if _, isBait := s.eng.IsBait(oa.ObjectName); !isBait {
				continue
			}
			h := fnv.New32a()
			fmt.Fprint(h, oa.ProcessID)
			queues[h.Sum32()%workers] <- oa
		case c := <-ctl:
			if c == svc.ParamChange {
				if err := s.reload(); err != nil {
					s.log.Printf("reload: %v", err)
				} else {
					s.log.Printf("configuration reloaded")
				}
			}
			s.safe("health check", func() { s.healthCheck(false) })
		case <-health.C:
			s.safe("health check", func() { s.healthCheck(false) })
			s.safe("learning check", s.learningCheck)
		case <-beat.C:
			s.saveBookmark()
		case <-dialRefresh.C:
			s.refreshDial(ctx)
		}
	}
}

func (s *server) subscribeLoop(ctx context.Context, out chan<- string) {
	for ctx.Err() == nil {
		st, _ := config.LoadState()
		bm := ""
		if st != nil {
			bm = st.Bookmark
		}
		sub, err := evtlog.Subscribe("Security", evtlog.BaitQuery, bm)
		if err != nil {
			s.log.Printf("subscribe: %v (retrying)", err)
			sleep(ctx, 5*time.Second)
			continue
		}
		s.mu.Lock()
		s.sub = sub
		s.mu.Unlock()
		s.log.Printf("watching Security log for bait access (resume=%v)", bm != "")
		s.once1.Do(func() { close(s.listening) })
		err = sub.Run(ctx, func(x string) {
			select {
			case out <- x:
			case <-ctx.Done():
			}
		})
		s.saveBookmark()
		s.mu.Lock()
		s.sub = nil
		s.mu.Unlock()
		sub.Close()
		if ctx.Err() == nil {
			s.log.Printf("subscription ended: %v (resubscribing)", err)
			sleep(ctx, 2*time.Second)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (s *server) saveBookmark() {
	s.mu.Lock()
	sub := s.sub
	s.mu.Unlock()
	if sub == nil {
		return
	}
	bm := sub.BookmarkXML()
	config.UpdateState(func(st *config.State) error {
		if bm != "" && strings.Contains(bm, "RecordId") {
			st.Bookmark = bm
		}
		st.Heartbeat = time.Now()
		return nil
	})
}

func (s *server) refreshDial(ctx context.Context) {
	s.mu.Lock()
	sec := s.secrets
	dial := s.dial
	s.mu.Unlock()
	if sec == nil || !sec.Phone.Enabled() || dial == nil {
		return
	}
	if st, _ := config.LoadState(); st != nil && st.Isolation != nil {
		return // DNS is blocked; keep the cache we have
	}
	dial.Refresh(ctx, notify.NewSender(sec.Phone, dial).Hosts())
	snap := dial.Snapshot()
	config.UpdateState(func(st *config.State) error { st.DialCache = snap; return nil })
}

// ---- engine.Ops ----

func (s *server) ImagePath(pid uint32) (string, error)     { return procinfo.ImagePath(pid) }
func (s *server) CreateTime(pid uint32) int64              { t, _ := procinfo.CreateTime(pid); return t }
func (s *server) Verify(p string) authenticode.Result      { return authenticode.Verify(p) }
func (s *server) SuspendTree(pid uint32) ([]uint32, error) { return procinfo.SuspendTree(pid) }
func (s *server) KillTree(pid uint32) error                { return procinfo.KillTree(pid) }
func (s *server) Forensics(pid uint32, p *alerts.Process)  { engine.ProcessDetails(pid, p) }
func (s *server) CommandLine(pid uint32) string            { c, _ := procinfo.CommandLine(pid); return c }
func (s *server) InjectedCode(pid uint32) (string, bool)   { return procinfo.InjectedCode(pid) }
func (s *server) BlockProgram(path string) error           { return netguard.BlockProgram(path) }
func (s *server) Isolate() error                           { return netguard.Isolate(s.selfExe) }
func (s *server) DisableAdapters() ([]string, error)       { return netguard.DisableAdapters() }
func (s *server) SaveAlert(a *alerts.Alert) error          { return alerts.Save(a) }
func (s *server) UpdateState(fn func(*config.State) error) error {
	return config.UpdateState(fn)
}
func (s *server) Logf(f string, a ...any) { s.log.Printf(f, a...) }

func (s *server) Resume(pids []uint32) {
	for _, p := range pids {
		procinfo.Resume(p)
	}
}

func (s *server) NotifyDesktop(a *alerts.Alert) {
	n, err := session.LaunchInActiveSessions(s.cliExe, "notify", a.ID)
	if err != nil {
		s.log.Printf("desktop notify: %v", err)
	} else if n == 0 {
		s.log.Printf("desktop notify: nobody logged in; alert %s kept in history", a.ID)
	}
}

func (s *server) NotifyPhone(a *alerts.Alert) {
	s.mu.Lock()
	sec, dial := s.secrets, s.dial
	s.mu.Unlock()
	if sec == nil || !sec.Phone.Enabled() {
		return
	}
	msg := notify.FromAlert(a)
	go func() {
		snd := notify.NewSender(sec.Phone, dial)
		var err error
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = snd.Send(ctx, msg)
			cancel()
			if err == nil {
				s.log.Printf("phone alert sent for %s", a.ID)
				return
			}
			time.Sleep(time.Duration(2<<i) * time.Second)
		}
		s.log.Printf("phone alert failed for %s: %v", a.ID, err)
	}()
}

func (s *server) PendingTest() *engine.TestRequest {
	b, err := os.ReadFile(paths.TestFile())
	if err != nil {
		return nil
	}
	var tr engine.TestRequest
	if json.Unmarshal(b, &tr) != nil || time.Since(tr.Since) > 2*time.Minute {
		return nil
	}
	return &tr
}

func (s *server) ClearTest() { os.Remove(paths.TestFile()) }

func (s *server) RetireDecoy(id, why string) {
	s.watch.Sync(nil) // let go of every bait while files are removed; reload re-arms the rest
	err := config.UpdateState(func(st *config.State) error {
		s.mu.Lock()
		u := s.cfg.User
		s.mu.Unlock()
		baits.Retire(st, u, id, why)
		return nil
	})
	if err != nil {
		s.log.Printf("retire %s: %v", id, err)
	}
	s.reload()
}

// UserSession reports whether pid runs in an interactive session (not the
// services session 0). Stealers run as the user; system processes don't.
func (s *server) UserSession(pid uint32) bool {
	var sid uint32
	if err := windows.ProcessIdToSessionId(pid, &sid); err != nil {
		return false
	}
	return sid != 0
}

// onOpen gets the program(s) that just opened a bait, identified precisely by
// package instant. Freeze what deserves it; the alert is raised asynchronously.
func (s *server) onOpen(path string, at time.Time, pids []uint32) {
	for _, pid := range pids {
		ok, why := s.eng.DecideInstantWhy(pid, path)
		if !ok {
			s.log.Printf("instant: pid %d let through: %s", pid, why)
			continue
		}
		frozen, err := procinfo.SuspendTree(pid)
		if err != nil && len(frozen) == 0 {
			s.eng.Unclaim(pid)
			s.log.Printf("instant freeze of pid %d failed: %v", pid, err)
			continue
		}
		img, _ := procinfo.ImagePath(pid)
		s.log.Printf("instant freeze: %s (pid %d) opened %s; frozen %d ms after the open", img, pid, path, time.Since(at).Milliseconds())
		go s.safe("instant-freeze alert", func() { s.eng.HandleOpen(pid, path, at, frozen) })
	}
}

var (
	selfHashOnce sync.Once
	selfHash     string
	hashCacheMu  sync.Mutex
	hashCache    = map[string]string{}
)

// IsSelf reports whether image is a copy of SENTIENT1's own executable, by SHA-256.
// (A path check isn't enough: the CLI may run from Downloads or a build folder.)
func (s *server) IsSelf(image string) bool {
	selfHashOnce.Do(func() { selfHash, _ = procinfo.FileSHA256(s.selfExe) })
	if selfHash == "" || image == "" {
		return false
	}
	return s.Hash(image) == selfHash
}

// Hash returns a file's SHA-256, cached by path, size and modification time.
func (s *server) Hash(image string) string {
	if image == "" {
		return ""
	}
	key := strings.ToLower(image)
	if fi, err := os.Stat(image); err == nil {
		key += fmt.Sprintf("|%d|%d", fi.Size(), fi.ModTime().UnixNano())
	}
	hashCacheMu.Lock()
	h, ok := hashCache[key]
	hashCacheMu.Unlock()
	if !ok {
		h, _ = procinfo.FileSHA256(image)
		hashCacheMu.Lock()
		hashCache[key] = h
		hashCacheMu.Unlock()
	}
	return h
}

// Elevated reports whether pid runs at high (admin) or system integrity, the
// same line UAC draws. (TokenIsElevated isn't enough: restricted tokens made
// from an admin, e.g. by `runas /trustlevel`, can still claim to be elevated.)
func (s *server) Elevated(pid uint32) bool {
	lvl, err := procinfo.IntegrityLevel(pid)
	if err != nil {
		return true // can't inspect it: don't instant-freeze
	}
	return lvl >= procinfo.IntegrityHigh
}

func (s *server) markReady() { s.once2.Do(func() { close(s.ready) }) }

// safe runs fn and, if it panics, logs the panic with its stack instead of
// crashing the service (which would drop the alert or response in progress).
func (s *server) safe(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Printf("PANIC in %s: %v\n%s", name, r, debug.Stack())
		}
	}()
	fn()
}
