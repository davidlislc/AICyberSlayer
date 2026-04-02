// Package siem provides adapters for forwarding events to external SIEM systems.
package siem

import (
	"context"

	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// Adapter is the common interface implemented by every SIEM output adapter.
// Adapters must be safe for concurrent use.
type Adapter interface {
	// Name returns a human-readable identifier for the adapter, e.g. "splunk".
	Name() string
	// Send forwards a batch of events to the SIEM system.
	Send(ctx context.Context, events []event.Event) error
	// Close releases any resources held by the adapter.
	Close() error
}
