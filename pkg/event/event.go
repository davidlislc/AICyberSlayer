// Package event defines the common event types used throughout the AICyberSlayer agent.
// All collectors produce Event values that are forwarded to Kafka and/or SIEM adapters.
package event

import "time"

// Category groups related event types.
type Category string

const (
	CategorySystem    Category = "system"
	CategoryNetwork   Category = "network"
	CategoryForensics Category = "forensics"
	CategoryWebServer Category = "webserver"
)

// Severity mirrors the RFC 5424 syslog severity levels.
type Severity string

const (
	SeverityDebug    Severity = "debug"
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Event is the canonical data structure sent to Kafka and SIEM adapters.
type Event struct {
	// ID is a unique identifier for this event (UUID v4).
	ID string `json:"id"`
	// Timestamp is when the event occurred (UTC).
	Timestamp time.Time `json:"timestamp"`
	// AgentID identifies the originating agent (hostname + configured ID).
	AgentID string `json:"agent_id"`
	// Hostname of the machine that generated the event.
	Hostname string `json:"hostname"`
	// OS is the operating system name (linux, darwin, windows).
	OS string `json:"os"`
	// Category classifies the event source.
	Category Category `json:"category"`
	// Type is a finer-grained label within the category, e.g. "process_list".
	Type string `json:"type"`
	// Severity of the event.
	Severity Severity `json:"severity"`
	// Payload carries the event-specific data as a generic map so that each
	// collector can emit structured fields without tight coupling.
	Payload map[string]any `json:"payload"`
}

// ProcessInfo describes a running OS process.
type ProcessInfo struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	Cmdline    string  `json:"cmdline"`
	Username   string  `json:"username"`
	CPUPercent float64 `json:"cpu_percent"`
	MemRSS     uint64  `json:"mem_rss_bytes"`
	Status     string  `json:"status"`
}

// CPUStats captures aggregate CPU utilisation.
type CPUStats struct {
	UsagePercent float64 `json:"usage_percent"`
	NumCores     int     `json:"num_cores"`
}

// MemStats captures memory utilisation.
type MemStats struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

// DiskStats captures disk utilisation for a single mount point.
type DiskStats struct {
	MountPoint  string  `json:"mount_point"`
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// NetworkConnection represents a single TCP/UDP socket entry.
type NetworkConnection struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        int32  `json:"pid"`
}

// NetworkInterfaceStats captures byte/packet counters for a NIC.
type NetworkInterfaceStats struct {
	Name        string `json:"name"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	Errout      uint64 `json:"errout"`
	Errin       uint64 `json:"errin"`
}

// ForensicsFileEvent is emitted when a file is created, modified, or deleted.
type ForensicsFileEvent struct {
	Path      string `json:"path"`
	Operation string `json:"operation"` // create | write | remove | rename | chmod
}

// LoginEvent represents a user login or logout.
type LoginEvent struct {
	Username  string    `json:"username"`
	Terminal  string    `json:"terminal"`
	Host      string    `json:"host"`
	EventType string    `json:"event_type"` // login | logout | failed
	Time      time.Time `json:"time"`
}

// WebServerLogEntry is a parsed HTTP access log line.
type WebServerLogEntry struct {
	ClientIP   string    `json:"client_ip"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Protocol   string    `json:"protocol"`
	StatusCode int       `json:"status_code"`
	BodyBytes  int64     `json:"body_bytes"`
	Referer    string    `json:"referer"`
	UserAgent  string    `json:"user_agent"`
}
