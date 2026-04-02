package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// WebServerCollector tails web server access log files and emits parsed HTTP
// access log entries.  It supports the NCSA Combined Log Format (default) and
// the NCSA Common Log Format.
type WebServerCollector struct {
	cfg      config.WebServerCollectorConfig
	agentID  string
	hostname string
	logger   *slog.Logger

	// offsets tracks the byte offset of the last read position per log file.
	offsets map[string]int64
}

// NewWebServerCollector creates a WebServerCollector.
func NewWebServerCollector(cfg config.WebServerCollectorConfig, agentID, hostname string, logger *slog.Logger) *WebServerCollector {
	return &WebServerCollector{
		cfg:      cfg,
		agentID:  agentID,
		hostname: hostname,
		logger:   logger,
		offsets:  make(map[string]int64),
	}
}

// Collect reads new lines from all configured log files and returns parsed
// events. Only lines added since the last call are processed (tail behaviour).
func (w *WebServerCollector) Collect(_ context.Context) ([]event.Event, error) {
	var events []event.Event
	for _, path := range w.cfg.LogFiles {
		evts, err := w.tailFile(path)
		if err != nil {
			w.logger.Warn("webserver: tail error", "path", path, "err", err)
			continue
		}
		events = append(events, evts...)
	}
	return events, nil
}

func (w *WebServerCollector) tailFile(path string) ([]event.Event, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	offset := w.offsets[path]
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		// If the file was rotated it may be shorter; restart from 0.
		if _, err2 := f.Seek(0, io.SeekStart); err2 != nil {
			return nil, err2
		}
		offset = 0
	}

	var events []event.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		entry, ok := w.parseLine(line)
		if !ok {
			continue
		}
		events = append(events, w.newEvent(entry))
	}
	if err := scanner.Err(); err != nil {
		return events, err
	}

	newOffset, _ := f.Seek(0, io.SeekCurrent)
	w.offsets[path] = newOffset
	return events, nil
}

// Combined log format pattern:
// 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref/" "Mozilla/5.0"
var combinedRE = regexp.MustCompile(
	`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?`)

// parseLine parses a single access log line.
func (w *WebServerCollector) parseLine(line string) (event.WebServerLogEntry, bool) {
	m := combinedRE.FindStringSubmatch(line)
	if m == nil {
		return event.WebServerLogEntry{}, false
	}

	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	statusCode, _ := strconv.Atoi(m[6])
	bodyBytes, _ := strconv.ParseInt(strings.TrimPrefix(m[7], "-"), 10, 64)

	return event.WebServerLogEntry{
		ClientIP:   m[1],
		Timestamp:  ts,
		Method:     m[3],
		Path:       m[4],
		Protocol:   m[5],
		StatusCode: statusCode,
		BodyBytes:  bodyBytes,
		Referer:    m[8],
		UserAgent:  m[9],
	}, true
}

func (w *WebServerCollector) newEvent(entry event.WebServerLogEntry) event.Event {
	sev := event.SeverityInfo
	if entry.StatusCode >= 400 && entry.StatusCode < 500 {
		sev = event.SeverityWarning
	} else if entry.StatusCode >= 500 {
		sev = event.SeverityCritical
	}

	return event.Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		AgentID:   w.agentID,
		Hostname:  w.hostname,
		OS:        runtime.GOOS,
		Category:  event.CategoryWebServer,
		Type:      "http_access",
		Severity:  sev,
		Payload:   toMap(entry),
	}
}
