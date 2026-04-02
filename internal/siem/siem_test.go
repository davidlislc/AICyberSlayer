package siem_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/internal/siem"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

func testEvent() event.Event {
	return event.Event{
		ID:        "evt-001",
		Timestamp: time.Now().UTC(),
		AgentID:   "agent-test",
		Hostname:  "testhost",
		OS:        "linux",
		Category:  event.CategorySystem,
		Type:      "cpu_stats",
		Severity:  event.SeverityInfo,
		Payload:   map[string]any{"usage_percent": 23.4},
	}
}

// ── Splunk ───────────────────────────────────────────────────────────────────

func TestSplunkAdapterName(t *testing.T) {
	a := siem.NewSplunkAdapter(config.SplunkConfig{}, discardLogger())
	if a.Name() != "splunk" {
		t.Errorf("Name: got %q want %q", a.Name(), "splunk")
	}
}

func TestSplunkAdapterSendsEvents(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"text":"Success","code":0}`)) //nolint:errcheck
	}))
	defer srv.Close()

	cfg := config.SplunkConfig{
		Enabled:  true,
		HECURL:   srv.URL,
		Token:    "test-token",
		Index:    "main",
		Insecure: false,
	}
	a := siem.NewSplunkAdapter(cfg, discardLogger())
	defer a.Close()

	if err := a.Send(context.Background(), []event.Event{testEvent()}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("server received no body")
	}
	var payload map[string]any
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("parse received payload: %v", err)
	}
	if _, ok := payload["event"]; !ok {
		t.Error("payload missing 'event' field")
	}
}

func TestSplunkAdapterEmptyEventsNoRequest(t *testing.T) {
	requested := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.SplunkConfig{HECURL: srv.URL, Token: "tok"}
	a := siem.NewSplunkAdapter(cfg, discardLogger())
	if err := a.Send(context.Background(), nil); err != nil {
		t.Fatalf("Send nil: %v", err)
	}
	if requested {
		t.Error("HTTP request should not have been made for empty event list")
	}
}

func TestSplunkAdapterHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.SplunkConfig{HECURL: srv.URL, Token: "tok"}
	a := siem.NewSplunkAdapter(cfg, discardLogger())
	err := a.Send(context.Background(), []event.Event{testEvent()})
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// ── Elastic ──────────────────────────────────────────────────────────────────

func TestElasticAdapterName(t *testing.T) {
	a := siem.NewElasticAdapter(config.ElasticConfig{}, discardLogger())
	if a.Name() != "elastic" {
		t.Errorf("Name: got %q want %q", a.Name(), "elastic")
	}
}

func TestElasticAdapterSendsEvents(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errors":false}`)) //nolint:errcheck
	}))
	defer srv.Close()

	cfg := config.ElasticConfig{
		Enabled:   true,
		Addresses: []string{srv.URL},
		Index:     "aicyberslayer",
	}
	a := siem.NewElasticAdapter(cfg, discardLogger())
	defer a.Close()

	if err := a.Send(context.Background(), []event.Event{testEvent()}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("server received no body")
	}
	// Bulk body should contain at least two lines (action + source).
	lines := strings.Split(strings.TrimSpace(string(received)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 ndjson lines, got %d", len(lines))
	}
}

func TestElasticAdapterNoAddressesError(t *testing.T) {
	cfg := config.ElasticConfig{Addresses: nil}
	a := siem.NewElasticAdapter(cfg, discardLogger())
	err := a.Send(context.Background(), []event.Event{testEvent()})
	if err == nil {
		t.Fatal("expected error for missing addresses, got nil")
	}
}

// ── Syslog ───────────────────────────────────────────────────────────────────

func TestSyslogAdapterSyslogFormat(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf, _ := io.ReadAll(conn)
		received <- string(buf)
	}()

	cfg := config.SyslogSIEMConfig{
		Enabled:  true,
		Network:  "tcp",
		Address:  ln.Addr().String(),
		Protocol: "syslog",
	}
	a, err := siem.NewSyslogAdapter(cfg, discardLogger())
	if err != nil {
		t.Fatalf("NewSyslogAdapter: %v", err)
	}

	if err := a.Send(context.Background(), []event.Event{testEvent()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	a.Close()

	select {
	case msg := <-received:
		if !strings.Contains(msg, "aicyberslayer") {
			t.Errorf("expected 'aicyberslayer' in syslog message, got: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogAdapterCEFFormat(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf, _ := io.ReadAll(conn)
		received <- string(buf)
	}()

	cfg := config.SyslogSIEMConfig{
		Enabled:  true,
		Network:  "tcp",
		Address:  ln.Addr().String(),
		Protocol: "cef",
	}
	a, err := siem.NewSyslogAdapter(cfg, discardLogger())
	if err != nil {
		t.Fatalf("NewSyslogAdapter: %v", err)
	}

	if err := a.Send(context.Background(), []event.Event{testEvent()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	a.Close()

	select {
	case msg := <-received:
		if !strings.HasPrefix(msg, "CEF:0|AICyberSlayer") {
			t.Errorf("expected CEF prefix, got: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CEF message")
	}
}
