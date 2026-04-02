package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// splunkHECEvent is the wrapper format expected by the Splunk HTTP Event Collector.
type splunkHECEvent struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host"`
	Index      string         `json:"index,omitempty"`
	SourceType string         `json:"sourcetype"`
	Event      map[string]any `json:"event"`
}

// SplunkAdapter forwards events to a Splunk HEC endpoint.
type SplunkAdapter struct {
	cfg    config.SplunkConfig
	client *http.Client
	logger *slog.Logger
}

// NewSplunkAdapter creates a SplunkAdapter.
func NewSplunkAdapter(cfg config.SplunkConfig, logger *slog.Logger) *SplunkAdapter {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, // #nosec G402 - operator-controlled flag
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &SplunkAdapter{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		logger: logger,
	}
}

// Name implements Adapter.
func (s *SplunkAdapter) Name() string { return "splunk" }

// Send encodes events in the Splunk HEC batch format and POSTs them.
func (s *SplunkAdapter) Send(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		he := splunkHECEvent{
			Time:       float64(e.Timestamp.UnixNano()) / 1e9,
			Host:       e.Hostname,
			Index:      s.cfg.Index,
			SourceType: fmt.Sprintf("aicyberslayer:%s:%s", e.Category, e.Type),
			Event:      toFlatMap(e),
		}
		if err := enc.Encode(he); err != nil {
			s.logger.Warn("splunk: marshal event", "id", e.ID, "err", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.HECURL, &buf)
	if err != nil {
		return fmt.Errorf("splunk: create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk: HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("splunk: unexpected status %d", resp.StatusCode)
	}
	s.logger.Debug("splunk: sent events", "count", len(events))
	return nil
}

// Close implements Adapter.
func (s *SplunkAdapter) Close() error { return nil }

// toFlatMap converts an event.Event to a flat map for embedding in the HEC payload.
func toFlatMap(e event.Event) map[string]any {
	m := map[string]any{
		"id":        e.ID,
		"timestamp": e.Timestamp.Format(time.RFC3339Nano),
		"agent_id":  e.AgentID,
		"hostname":  e.Hostname,
		"os":        e.OS,
		"category":  string(e.Category),
		"type":      e.Type,
		"severity":  string(e.Severity),
	}
	for k, v := range e.Payload {
		m[k] = v
	}
	return m
}
