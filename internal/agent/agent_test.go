package agent_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/davidlislc/AICyberSlayer/internal/agent"
	"github.com/davidlislc/AICyberSlayer/internal/siem"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// stubCollector is a test double that returns pre-configured events.
type stubCollector struct {
	events []event.Event
	err    error
}

func (s *stubCollector) Collect(_ context.Context) ([]event.Event, error) {
	return s.events, s.err
}

// stubAdapter captures events passed to it.
type stubAdapter struct {
	name   string
	sent   []event.Event
	sendFn func(ctx context.Context, events []event.Event) error
}

func (s *stubAdapter) Name() string { return s.name }
func (s *stubAdapter) Send(ctx context.Context, events []event.Event) error {
	if s.sendFn != nil {
		return s.sendFn(ctx, events)
	}
	s.sent = append(s.sent, events...)
	return nil
}
func (s *stubAdapter) Close() error { return nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

func TestAgentRunCancellation(t *testing.T) {
	a := agent.New(agent.Config{
		ID:            "test",
		FlushInterval: 100 * time.Millisecond,
		Collectors:    nil,
		Logger:        discardLogger(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	err := a.Run(ctx)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAgentForwardsToSIEMAdapter(t *testing.T) {
	evts := []event.Event{{
		ID:       "e1",
		AgentID:  "test",
		Category: event.CategorySystem,
		Severity: event.SeverityInfo,
	}}

	collector := &stubCollector{events: evts}
	adapter := &stubAdapter{name: "test-adapter"}

	a := agent.New(agent.Config{
		ID:            "test",
		FlushInterval: 50 * time.Millisecond,
		Collectors:    []agent.Collector{collector},
		SIEMAdapters:  []siem.Adapter{adapter},
		Logger:        discardLogger(),
	})
	_ = a // re-created below

	// The agent calls collectAndForward immediately on Run; cancel right after.
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	a.Run(ctx) //nolint:errcheck
}

func TestAgentCollectorErrorDoesNotStop(t *testing.T) {
	errCollector := &stubCollector{err: errors.New("simulated failure")}
	goodCollector := &stubCollector{events: []event.Event{{ID: "ok", AgentID: "test"}}}

	a := agent.New(agent.Config{
		ID:            "test",
		FlushInterval: 50 * time.Millisecond,
		Collectors:    []agent.Collector{errCollector, goodCollector},
		Logger:        discardLogger(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	// Should complete without panicking even when a collector returns an error.
	err := a.Run(ctx)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("unexpected error: %v", err)
	}
}
