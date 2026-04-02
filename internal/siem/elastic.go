package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// ElasticAdapter forwards events to an Elasticsearch / Elastic SIEM index using
// the Bulk API.
type ElasticAdapter struct {
	cfg    config.ElasticConfig
	client *http.Client
	logger *slog.Logger
}

// NewElasticAdapter creates an ElasticAdapter.
func NewElasticAdapter(cfg config.ElasticConfig, logger *slog.Logger) *ElasticAdapter {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, // #nosec G402 - operator-controlled flag
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &ElasticAdapter{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		logger: logger,
	}
}

// Name implements Adapter.
func (e *ElasticAdapter) Name() string { return "elastic" }

// Send encodes events using the Elasticsearch Bulk API format and POSTs them.
func (e *ElasticAdapter) Send(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}
	if len(e.cfg.Addresses) == 0 {
		return fmt.Errorf("elastic: no addresses configured")
	}

	index := e.cfg.Index
	if index == "" {
		index = "aicyberslayer"
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		// Action line
		action := map[string]any{"index": map[string]any{"_index": index, "_id": ev.ID}}
		if err := enc.Encode(action); err != nil {
			continue
		}
		// Source line
		doc := toFlatMap(ev)
		if err := enc.Encode(doc); err != nil {
			e.logger.Warn("elastic: marshal event", "id", ev.ID, "err", err)
		}
	}

	url := strings.TrimRight(e.cfg.Addresses[0], "/") + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("elastic: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if e.cfg.Username != "" {
		req.SetBasicAuth(e.cfg.Username, e.cfg.Password)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("elastic: HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("elastic: unexpected status %d", resp.StatusCode)
	}
	e.logger.Debug("elastic: sent events", "count", len(events))
	return nil
}

// Close implements Adapter.
func (e *ElasticAdapter) Close() error { return nil }
