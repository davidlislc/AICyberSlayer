// Package agent implements the AICyberSlayer agent orchestrator.
// It wires together all collectors, the Kafka producer, and any SIEM adapters,
// then drives periodic collection on a configurable flush interval.
package agent

import (
	"context"
	"log/slog"
	"os"
	"time"

	kafkaclient "github.com/davidlislc/AICyberSlayer/internal/kafka"
	"github.com/davidlislc/AICyberSlayer/internal/siem"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// Collector is the interface that all data collectors must satisfy.
type Collector interface {
	Collect(ctx context.Context) ([]event.Event, error)
}

// Agent orchestrates data collection and event forwarding.
type Agent struct {
	id            string
	hostname      string
	flushInterval time.Duration
	collectors    []Collector
	producer      *kafkaclient.Producer
	siemAdapters  []siem.Adapter
	logger        *slog.Logger
}

// Config is the agent construction configuration.
type Config struct {
	ID            string
	FlushInterval time.Duration
	Collectors    []Collector
	Producer      *kafkaclient.Producer
	SIEMAdapters  []siem.Adapter
	Logger        *slog.Logger
}

// New creates an Agent from the supplied Config.
func New(cfg Config) *Agent {
	id := cfg.ID
	if id == "" {
		id, _ = os.Hostname()
	}
	hostname, _ := os.Hostname()

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Agent{
		id:            id,
		hostname:      hostname,
		flushInterval: cfg.FlushInterval,
		collectors:    cfg.Collectors,
		producer:      cfg.Producer,
		siemAdapters:  cfg.SIEMAdapters,
		logger:        logger,
	}
}

// Run starts the collection loop and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent starting", "id", a.id, "hostname", a.hostname,
		"flush_interval", a.flushInterval, "collectors", len(a.collectors))

	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()

	// Collect immediately on start, then on each tick.
	a.collectAndForward(ctx)

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent shutting down")
			return ctx.Err()
		case <-ticker.C:
			a.collectAndForward(ctx)
		}
	}
}

// collectAndForward runs all collectors and forwards the resulting events.
func (a *Agent) collectAndForward(ctx context.Context) {
	var all []event.Event
	for _, c := range a.collectors {
		evts, err := c.Collect(ctx)
		if err != nil {
			a.logger.Warn("collection error", "collector", collectorName(c), "err", err)
			continue
		}
		all = append(all, evts...)
	}

	if len(all) == 0 {
		return
	}

	a.logger.Info("collected events", "count", len(all))

	if a.producer != nil {
		if err := a.producer.Publish(ctx, a.id, all); err != nil {
			a.logger.Error("kafka publish failed", "err", err)
		}
	}

	for _, adapter := range a.siemAdapters {
		if err := adapter.Send(ctx, all); err != nil {
			a.logger.Error("siem adapter send failed", "adapter", adapter.Name(), "err", err)
		}
	}
}

// collectorName returns a best-effort name for a Collector for logging.
func collectorName(c Collector) string {
	if n, ok := c.(interface{ Name() string }); ok {
		return n.Name()
	}
	return "unknown"
}
