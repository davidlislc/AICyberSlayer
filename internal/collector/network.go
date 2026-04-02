package collector

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// NetworkCollector collects network interface statistics and socket connections.
type NetworkCollector struct {
	cfg      config.NetworkCollectorConfig
	agentID  string
	hostname string
	logger   *slog.Logger
}

// NewNetworkCollector creates a NetworkCollector.
func NewNetworkCollector(cfg config.NetworkCollectorConfig, agentID, hostname string, logger *slog.Logger) *NetworkCollector {
	return &NetworkCollector{
		cfg:      cfg,
		agentID:  agentID,
		hostname: hostname,
		logger:   logger,
	}
}

// Collect gathers network telemetry and returns events.
func (n *NetworkCollector) Collect(_ context.Context) ([]event.Event, error) {
	var events []event.Event

	ifaceEvent, err := n.collectInterfaces()
	if err != nil {
		n.logger.Warn("network: interface collection failed", "err", err)
	} else {
		events = append(events, ifaceEvent)
	}

	if n.cfg.CollectConnections {
		connEvent, err := n.collectConnections()
		if err != nil {
			n.logger.Warn("network: connection collection failed", "err", err)
		} else {
			events = append(events, connEvent)
		}
	}

	return events, nil
}

func (n *NetworkCollector) collectInterfaces() (event.Event, error) {
	counters, err := net.IOCounters(true)
	if err != nil {
		return event.Event{}, fmt.Errorf("net.IOCounters: %w", err)
	}

	stats := make([]event.NetworkInterfaceStats, 0, len(counters))
	for _, c := range counters {
		stats = append(stats, event.NetworkInterfaceStats{
			Name:        c.Name,
			BytesSent:   c.BytesSent,
			BytesRecv:   c.BytesRecv,
			PacketsSent: c.PacketsSent,
			PacketsRecv: c.PacketsRecv,
			Errout:      c.Errout,
			Errin:       c.Errin,
		})
	}

	return n.newEvent("interface_stats", event.SeverityInfo, map[string]any{
		"interfaces": stats,
	}), nil
}

func (n *NetworkCollector) collectConnections() (event.Event, error) {
	conns, err := net.Connections("all")
	if err != nil {
		return event.Event{}, fmt.Errorf("net.Connections: %w", err)
	}

	list := make([]event.NetworkConnection, 0, len(conns))
	for _, c := range conns {
		list = append(list, event.NetworkConnection{
			Protocol:   kindToProtocol(c.Type),
			LocalAddr:  fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
			State:      c.Status,
			PID:        c.Pid,
		})
	}

	return n.newEvent("connection_table", event.SeverityInfo, map[string]any{
		"connection_count": len(list),
		"connections":      list,
	}), nil
}

// kindToProtocol converts the gopsutil connection kind to a human-readable name.
func kindToProtocol(kind uint32) string {
	switch kind {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return "unknown"
	}
}

func (n *NetworkCollector) newEvent(typ string, severity event.Severity, payload map[string]any) event.Event {
	return event.Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		AgentID:   n.agentID,
		Hostname:  n.hostname,
		OS:        runtime.GOOS,
		Category:  event.CategoryNetwork,
		Type:      typ,
		Severity:  severity,
		Payload:   payload,
	}
}
