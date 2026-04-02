// Package collector provides data collection implementations for the AICyberSlayer agent.
// Each sub-collector gathers a specific class of telemetry and emits Event values.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// SystemCollector collects CPU, memory, disk, and process information.
type SystemCollector struct {
	cfg      config.SystemCollectorConfig
	agentID  string
	hostname string
	logger   *slog.Logger
}

// NewSystemCollector creates a SystemCollector.
func NewSystemCollector(cfg config.SystemCollectorConfig, agentID, hostname string, logger *slog.Logger) *SystemCollector {
	return &SystemCollector{
		cfg:      cfg,
		agentID:  agentID,
		hostname: hostname,
		logger:   logger,
	}
}

// Collect gathers a snapshot of system metrics and returns the resulting events.
// It is safe to call concurrently.
func (s *SystemCollector) Collect(_ context.Context) ([]event.Event, error) {
	var events []event.Event

	cpuEvent, err := s.collectCPU()
	if err != nil {
		s.logger.Warn("system: CPU collection failed", "err", err)
	} else {
		events = append(events, cpuEvent)
	}

	memEvent, err := s.collectMemory()
	if err != nil {
		s.logger.Warn("system: memory collection failed", "err", err)
	} else {
		events = append(events, memEvent)
	}

	diskEvents, err := s.collectDisks()
	if err != nil {
		s.logger.Warn("system: disk collection failed", "err", err)
	} else {
		events = append(events, diskEvents...)
	}

	if s.cfg.CollectProcesses {
		procEvent, err := s.collectProcesses()
		if err != nil {
			s.logger.Warn("system: process collection failed", "err", err)
		} else {
			events = append(events, procEvent)
		}
	}

	return events, nil
}

func (s *SystemCollector) collectCPU() (event.Event, error) {
	percentages, err := cpu.Percent(500*time.Millisecond, false)
	if err != nil {
		return event.Event{}, fmt.Errorf("cpu.Percent: %w", err)
	}
	if len(percentages) == 0 {
		return event.Event{}, fmt.Errorf("cpu.Percent: empty result")
	}

	stats := event.CPUStats{
		UsagePercent: percentages[0],
		NumCores:     runtime.NumCPU(),
	}
	return s.newEvent("cpu_stats", event.SeverityInfo, toMap(stats)), nil
}

func (s *SystemCollector) collectMemory() (event.Event, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return event.Event{}, fmt.Errorf("mem.VirtualMemory: %w", err)
	}

	stats := event.MemStats{
		TotalBytes:     v.Total,
		AvailableBytes: v.Available,
		UsedPercent:    v.UsedPercent,
	}
	return s.newEvent("mem_stats", event.SeverityInfo, toMap(stats)), nil
}

func (s *SystemCollector) collectDisks() ([]event.Event, error) {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil, fmt.Errorf("disk.Partitions: %w", err)
	}

	var events []event.Event
	for _, p := range parts {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			s.logger.Debug("system: disk usage error", "mount", p.Mountpoint, "err", err)
			continue
		}
		stats := event.DiskStats{
			MountPoint:  p.Mountpoint,
			TotalBytes:  usage.Total,
			FreeBytes:   usage.Free,
			UsedPercent: usage.UsedPercent,
		}
		events = append(events, s.newEvent("disk_stats", event.SeverityInfo, toMap(stats)))
	}
	return events, nil
}

func (s *SystemCollector) collectProcesses() (event.Event, error) {
	procs, err := process.Processes()
	if err != nil {
		return event.Event{}, fmt.Errorf("process.Processes: %w", err)
	}

	list := make([]event.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		info := event.ProcessInfo{PID: p.Pid}

		if name, err := p.Name(); err == nil {
			info.Name = name
		}
		if cmdline, err := p.Cmdline(); err == nil {
			info.Cmdline = cmdline
		}
		if user, err := p.Username(); err == nil {
			info.Username = user
		}
		if cpuPct, err := p.CPUPercent(); err == nil {
			info.CPUPercent = cpuPct
		}
		if memInfo, err := p.MemoryInfo(); err == nil && memInfo != nil {
			info.MemRSS = memInfo.RSS
		}
		if status, err := p.Status(); err == nil && len(status) > 0 {
			info.Status = status[0]
		}
		list = append(list, info)
	}

	return s.newEvent("process_list", event.SeverityInfo, map[string]any{
		"process_count": len(list),
		"processes":     list,
	}), nil
}

func (s *SystemCollector) newEvent(typ string, severity event.Severity, payload map[string]any) event.Event {
	return event.Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		AgentID:   s.agentID,
		Hostname:  s.hostname,
		OS:        runtime.GOOS,
		Category:  event.CategorySystem,
		Type:      typ,
		Severity:  severity,
		Payload:   payload,
	}
}

// toMap serialises a struct to map[string]any via JSON round-trip.
func toMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"_error": err.Error()}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"_error": err.Error()}
	}
	return m
}
