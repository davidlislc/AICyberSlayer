package event_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

func TestEventJSONRoundTrip(t *testing.T) {
	e := event.Event{
		ID:        "test-id-1",
		Timestamp: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		AgentID:   "agent-001",
		Hostname:  "myhost",
		OS:        "linux",
		Category:  event.CategorySystem,
		Type:      "cpu_stats",
		Severity:  event.SeverityInfo,
		Payload: map[string]any{
			"usage_percent": 42.5,
			"num_cores":     8,
		},
	}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got event.Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != e.ID {
		t.Errorf("ID: got %q want %q", got.ID, e.ID)
	}
	if got.AgentID != e.AgentID {
		t.Errorf("AgentID: got %q want %q", got.AgentID, e.AgentID)
	}
	if got.Category != e.Category {
		t.Errorf("Category: got %q want %q", got.Category, e.Category)
	}
	if got.Severity != e.Severity {
		t.Errorf("Severity: got %q want %q", got.Severity, e.Severity)
	}
}

func TestSeverityConstants(t *testing.T) {
	severities := []event.Severity{
		event.SeverityDebug,
		event.SeverityInfo,
		event.SeverityWarning,
		event.SeverityCritical,
	}
	for _, s := range severities {
		if s == "" {
			t.Errorf("severity constant is empty")
		}
	}
}

func TestCategoryConstants(t *testing.T) {
	categories := []event.Category{
		event.CategorySystem,
		event.CategoryNetwork,
		event.CategoryForensics,
		event.CategoryWebServer,
	}
	for _, c := range categories {
		if c == "" {
			t.Errorf("category constant is empty")
		}
	}
}
