package collector_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/davidlislc/AICyberSlayer/internal/collector"
	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// TestSystemCollectorReturnsEvents verifies that the system collector produces
// at least CPU and memory events without error.
func TestSystemCollectorReturnsEvents(t *testing.T) {
	cfg := config.SystemCollectorConfig{
		Enabled:          true,
		CollectProcesses: false, // skip process collection to keep test fast
	}
	c := collector.NewSystemCollector(cfg, "test-agent", "test-host", discardLogger())

	evts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: unexpected error: %v", err)
	}
	if len(evts) == 0 {
		t.Fatal("Collect: expected at least one event, got 0")
	}

	for _, e := range evts {
		if e.ID == "" {
			t.Error("event has empty ID")
		}
		if e.Timestamp.IsZero() {
			t.Error("event has zero timestamp")
		}
		if e.Category != event.CategorySystem {
			t.Errorf("event category: got %q want %q", e.Category, event.CategorySystem)
		}
		if e.AgentID != "test-agent" {
			t.Errorf("AgentID: got %q", e.AgentID)
		}
	}
}

// TestNetworkCollectorReturnsEvents verifies that the network collector returns
// at least one event (interface stats).
func TestNetworkCollectorReturnsEvents(t *testing.T) {
	cfg := config.NetworkCollectorConfig{
		Enabled:            true,
		CollectConnections: false,
	}
	c := collector.NewNetworkCollector(cfg, "test-agent", "test-host", discardLogger())

	evts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: unexpected error: %v", err)
	}
	if len(evts) == 0 {
		t.Fatal("Collect: expected at least one event, got 0")
	}

	for _, e := range evts {
		if e.Category != event.CategoryNetwork {
			t.Errorf("event category: got %q want %q", e.Category, event.CategoryNetwork)
		}
	}
}

// TestForensicsCollectorNoWatchPaths verifies that the forensics collector
// works without any watch paths configured (login collection only).
func TestForensicsCollectorNoWatchPaths(t *testing.T) {
	cfg := config.ForensicsCollectorConfig{
		Enabled:       true,
		WatchPaths:    nil,
		CollectLogins: false, // avoid needing root to read /var/log/auth.log
	}
	c, err := collector.NewForensicsCollector(cfg, "test-agent", "test-host", discardLogger())
	if err != nil {
		t.Fatalf("NewForensicsCollector: %v", err)
	}
	defer c.Close()

	// No paths to watch, no login collection → should return empty slice without error.
	evts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	_ = evts // may be empty, that's fine
}

// TestWebServerCollectorEmptyLogFiles verifies that an empty log file list
// results in no events and no error.
func TestWebServerCollectorEmptyLogFiles(t *testing.T) {
	cfg := config.WebServerCollectorConfig{
		Enabled:  true,
		LogFiles: nil,
		Format:   "combined",
	}
	c := collector.NewWebServerCollector(cfg, "test-agent", "test-host", discardLogger())
	evts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(evts) != 0 {
		t.Errorf("expected 0 events for empty log file list, got %d", len(evts))
	}
}

// TestWebServerCollectorParsesCombinedLog verifies parsing of combined format
// log entries.
func TestWebServerCollectorParsesCombinedLog(t *testing.T) {
	// Write a sample combined log line to a temp file.
	logLine := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08"` + "\n"

	f, err := os.CreateTemp(t.TempDir(), "access-*.log")
	if err != nil {
		t.Fatalf("create temp log: %v", err)
	}
	if _, err := f.WriteString(logLine); err != nil {
		t.Fatalf("write log: %v", err)
	}
	f.Close()

	cfg := config.WebServerCollectorConfig{
		Enabled:  true,
		LogFiles: []string{f.Name()},
		Format:   "combined",
	}
	c := collector.NewWebServerCollector(cfg, "test-agent", "test-host", discardLogger())
	evts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}

	e := evts[0]
	if e.Category != event.CategoryWebServer {
		t.Errorf("category: got %q want %q", e.Category, event.CategoryWebServer)
	}
	if e.Type != "http_access" {
		t.Errorf("type: got %q want %q", e.Type, "http_access")
	}
	if ip, _ := e.Payload["client_ip"].(string); ip != "127.0.0.1" {
		t.Errorf("client_ip: got %q", ip)
	}
	if code, ok := e.Payload["status_code"].(float64); !ok || int(code) != 200 {
		t.Errorf("status_code: got %v", e.Payload["status_code"])
	}
}

// TestWebServerCollectorTailBehaviour verifies that successive calls to Collect
// only return newly appended lines.
func TestWebServerCollectorTailBehaviour(t *testing.T) {
	line1 := `192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 100 "-" "curl/7.0"` + "\n"
	line2 := `10.0.0.1 - - [10/Oct/2000:14:00:00 -0700] "POST /b HTTP/1.1" 500 0 "-" "python/3"` + "\n"

	f, err := os.CreateTemp(t.TempDir(), "access-*.log")
	if err != nil {
		t.Fatalf("create temp log: %v", err)
	}
	if _, err := f.WriteString(line1); err != nil {
		t.Fatalf("write log: %v", err)
	}
	f.Close()

	cfg := config.WebServerCollectorConfig{
		Enabled:  true,
		LogFiles: []string{f.Name()},
		Format:   "combined",
	}
	c := collector.NewWebServerCollector(cfg, "test-agent", "test-host", discardLogger())

	// First collect: should see line1.
	evts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	if len(evts) != 1 {
		t.Fatalf("first collect: expected 1 event, got %d", len(evts))
	}

	// Append line2.
	ff, err := os.OpenFile(f.Name(), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("reopen log: %v", err)
	}
	if _, err := ff.WriteString(line2); err != nil {
		t.Fatalf("append log: %v", err)
	}
	ff.Close()

	// Second collect: should only see line2.
	evts, err = c.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if len(evts) != 1 {
		t.Fatalf("second collect: expected 1 event, got %d", len(evts))
	}
	if sev := evts[0].Severity; sev != event.SeverityCritical {
		t.Errorf("500 response should be critical, got %q", sev)
	}
}
