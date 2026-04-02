package collector

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// ForensicsCollector monitors filesystem paths for changes and parses login
// records from the OS authentication logs.
type ForensicsCollector struct {
	cfg      config.ForensicsCollectorConfig
	agentID  string
	hostname string
	logger   *slog.Logger

	mu      sync.Mutex
	pending []event.Event

	watcher *fsnotify.Watcher
}

// NewForensicsCollector creates a ForensicsCollector and starts background
// filesystem watching if watch paths are configured.
func NewForensicsCollector(cfg config.ForensicsCollectorConfig, agentID, hostname string, logger *slog.Logger) (*ForensicsCollector, error) {
	fc := &ForensicsCollector{
		cfg:      cfg,
		agentID:  agentID,
		hostname: hostname,
		logger:   logger,
	}

	if len(cfg.WatchPaths) > 0 {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		for _, p := range cfg.WatchPaths {
			if err := w.Add(p); err != nil {
				logger.Warn("forensics: cannot watch path", "path", p, "err", err)
			}
		}
		fc.watcher = w
		go fc.watchLoop()
	}

	return fc, nil
}

// watchLoop receives fsnotify events and buffers them for the next Collect call.
func (f *ForensicsCollector) watchLoop() {
	for {
		select {
		case ev, ok := <-f.watcher.Events:
			if !ok {
				return
			}
			fe := event.ForensicsFileEvent{
				Path:      ev.Name,
				Operation: fsOp(ev.Op),
			}
			e := f.newEvent("file_event", event.SeverityInfo, toMap(fe))
			f.mu.Lock()
			f.pending = append(f.pending, e)
			f.mu.Unlock()

		case err, ok := <-f.watcher.Errors:
			if !ok {
				return
			}
			f.logger.Warn("forensics: watcher error", "err", err)
		}
	}
}

// Collect drains buffered file-system events and, if configured, reads login
// records from the OS auth log.
func (f *ForensicsCollector) Collect(_ context.Context) ([]event.Event, error) {
	f.mu.Lock()
	events := f.pending
	f.pending = nil
	f.mu.Unlock()

	if f.cfg.CollectLogins {
		loginEvents := f.collectLogins()
		events = append(events, loginEvents...)
	}

	return events, nil
}

// Close releases the underlying watcher resources.
func (f *ForensicsCollector) Close() error {
	if f.watcher != nil {
		return f.watcher.Close()
	}
	return nil
}

// collectLogins reads the OS-specific auth/login log and returns parsed events.
func (f *ForensicsCollector) collectLogins() []event.Event {
	logPath := authLogPath()
	if logPath == "" {
		return nil
	}

	file, err := os.Open(logPath) // #nosec G304
	if err != nil {
		f.logger.Debug("forensics: cannot open auth log", "path", logPath, "err", err)
		return nil
	}
	defer file.Close()

	var events []event.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		le, ok := parseAuthLogLine(line)
		if !ok {
			continue
		}
		events = append(events, f.newEvent("login_event", loginSeverity(le.EventType), toMap(le)))
	}
	return events
}

// authLogPath returns the platform-specific authentication log path.
func authLogPath() string {
	switch runtime.GOOS {
	case "linux":
		// Prefer journald-less distros; fall back to /var/log/auth.log
		if _, err := os.Stat("/var/log/auth.log"); err == nil {
			return "/var/log/auth.log"
		}
		if _, err := os.Stat("/var/log/secure"); err == nil {
			return "/var/log/secure"
		}
	case "darwin":
		return "/var/log/system.log"
	}
	return ""
}

// parseAuthLogLine attempts to extract a LoginEvent from a single auth log line.
func parseAuthLogLine(line string) (event.LoginEvent, bool) {
	lower := strings.ToLower(line)

	var evType string
	switch {
	case strings.Contains(lower, "accepted password") || strings.Contains(lower, "session opened"):
		evType = "login"
	case strings.Contains(lower, "session closed") || strings.Contains(lower, "logged out"):
		evType = "logout"
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure"):
		evType = "failed"
	default:
		return event.LoginEvent{}, false
	}

	// Best-effort username extraction: "for <user>" or "user=<user>"
	username := extractField(line, "for ")
	if username == "" {
		username = extractField(line, "user=")
	}

	return event.LoginEvent{
		EventType: evType,
		Username:  username,
		Time:      time.Now().UTC(),
	}, true
}

func extractField(line, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(prefix):]
	if rest == "" {
		return ""
	}
	// Take up to the first whitespace.
	end := strings.IndexAny(rest, " \t\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func loginSeverity(evType string) event.Severity {
	if evType == "failed" {
		return event.SeverityWarning
	}
	return event.SeverityInfo
}

func fsOp(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create != 0:
		return "create"
	case op&fsnotify.Write != 0:
		return "write"
	case op&fsnotify.Remove != 0:
		return "remove"
	case op&fsnotify.Rename != 0:
		return "rename"
	case op&fsnotify.Chmod != 0:
		return "chmod"
	default:
		return "unknown"
	}
}

func (f *ForensicsCollector) newEvent(typ string, severity event.Severity, payload map[string]any) event.Event {
	return event.Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		AgentID:   f.agentID,
		Hostname:  f.hostname,
		OS:        runtime.GOOS,
		Category:  event.CategoryForensics,
		Type:      typ,
		Severity:  severity,
		Payload:   payload,
	}
}
