package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// SyslogAdapter forwards events as RFC 5424 syslog messages or ArcSight CEF
// messages over TCP or UDP to a central syslog / SIEM receiver.
type SyslogAdapter struct {
	cfg    config.SyslogSIEMConfig
	conn   net.Conn
	logger *slog.Logger
}

// NewSyslogAdapter creates a SyslogAdapter and opens the network connection.
func NewSyslogAdapter(cfg config.SyslogSIEMConfig, logger *slog.Logger) (*SyslogAdapter, error) {
	conn, err := net.DialTimeout(cfg.Network, cfg.Address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("syslog: dial %s://%s: %w", cfg.Network, cfg.Address, err)
	}
	return &SyslogAdapter{cfg: cfg, conn: conn, logger: logger}, nil
}

// Name implements Adapter.
func (s *SyslogAdapter) Name() string { return "syslog" }

// Send encodes each event as a syslog or CEF message and writes it to the
// established connection.
func (s *SyslogAdapter) Send(_ context.Context, events []event.Event) error {
	for _, e := range events {
		var line string
		switch strings.ToLower(s.cfg.Protocol) {
		case "cef":
			line = toCEF(e)
		default:
			line = toSyslog(e)
		}
		if _, err := fmt.Fprintln(s.conn, line); err != nil {
			return fmt.Errorf("syslog: write: %w", err)
		}
	}
	s.logger.Debug("syslog: sent events", "count", len(events))
	return nil
}

// Close implements Adapter.
func (s *SyslogAdapter) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// toSyslog formats an event as an RFC 5424 syslog message.
func toSyslog(e event.Event) string {
	priority := severityToPriority(e.Severity)
	ts := e.Timestamp.Format(time.RFC3339)
	payload, _ := json.Marshal(e.Payload)
	return fmt.Sprintf("<%d>1 %s %s aicyberslayer - %s - %s",
		priority, ts, e.Hostname, e.ID, string(payload))
}

// toCEF formats an event as a CEF (ArcSight Common Event Format) message.
func toCEF(e event.Event) string {
	severity := cefSeverity(e.Severity)
	ts := e.Timestamp.Format(time.RFC3339)
	payload, _ := json.Marshal(e.Payload)
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	return fmt.Sprintf("CEF:0|AICyberSlayer|Agent|1.0|%s:%s|%s|%s|rt=%s msg=%s",
		e.Category, e.Type, e.Type, severity, ts, string(payload))
}

func severityToPriority(s event.Severity) int {
	// Facility: security (4<<3 = 32); severity: RFC 5424 mapping.
	switch s {
	case event.SeverityDebug:
		return 32 + 7
	case event.SeverityInfo:
		return 32 + 6
	case event.SeverityWarning:
		return 32 + 4
	case event.SeverityCritical:
		return 32 + 2
	default:
		return 32 + 6
	}
}

func cefSeverity(s event.Severity) string {
	switch s {
	case event.SeverityDebug:
		return "0"
	case event.SeverityInfo:
		return "3"
	case event.SeverityWarning:
		return "6"
	case event.SeverityCritical:
		return "9"
	default:
		return "3"
	}
}
