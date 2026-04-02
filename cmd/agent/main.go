// AICyberSlayer agent – collects system, network, forensics, and web server
// telemetry and forwards it to Apache Kafka and/or SIEM adapters.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/davidlislc/AICyberSlayer/internal/agent"
	"github.com/davidlislc/AICyberSlayer/internal/collector"
	"github.com/davidlislc/AICyberSlayer/internal/config"
	kafkaclient "github.com/davidlislc/AICyberSlayer/internal/kafka"
	"github.com/davidlislc/AICyberSlayer/internal/siem"
)

func main() {
	configPath := flag.String("config", "config/agent.yaml", "Path to agent configuration file")
	flag.Parse()

	// Bootstrap a plain text logger until the config has been read.
	bootstrapLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		bootstrapLogger.Error("failed to load config", "path", *configPath, "err", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.Logging)

	hostname, _ := os.Hostname()
	agentID := cfg.Agent.ID
	if agentID == "" {
		agentID = hostname
	}

	// ── Kafka producer ──────────────────────────────────────────────────────
	producer, err := kafkaclient.NewProducer(cfg.Kafka, logger)
	if err != nil {
		logger.Error("failed to create Kafka producer", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := producer.Close(); err != nil {
			logger.Warn("kafka producer close", "err", err)
		}
	}()

	// ── SIEM adapters ────────────────────────────────────────────────────────
	var adapters []siem.Adapter

	if cfg.SIEM.Splunk.Enabled {
		adapters = append(adapters, siem.NewSplunkAdapter(cfg.SIEM.Splunk, logger))
		logger.Info("SIEM adapter enabled", "adapter", "splunk")
	}
	if cfg.SIEM.Elastic.Enabled {
		adapters = append(adapters, siem.NewElasticAdapter(cfg.SIEM.Elastic, logger))
		logger.Info("SIEM adapter enabled", "adapter", "elastic")
	}
	if cfg.SIEM.SyslogSIEM.Enabled {
		a, err := siem.NewSyslogAdapter(cfg.SIEM.SyslogSIEM, logger)
		if err != nil {
			logger.Error("failed to create syslog adapter", "err", err)
		} else {
			adapters = append(adapters, a)
			logger.Info("SIEM adapter enabled", "adapter", "syslog")
		}
	}
	defer func() {
		for _, a := range adapters {
			if err := a.Close(); err != nil {
				logger.Warn("siem adapter close", "adapter", a.Name(), "err", err)
			}
		}
	}()

	// ── Collectors ───────────────────────────────────────────────────────────
	var collectors []agent.Collector

	if cfg.Collector.System.Enabled {
		collectors = append(collectors,
			collector.NewSystemCollector(cfg.Collector.System, agentID, hostname, logger))
		logger.Info("collector enabled", "collector", "system")
	}
	if cfg.Collector.Network.Enabled {
		collectors = append(collectors,
			collector.NewNetworkCollector(cfg.Collector.Network, agentID, hostname, logger))
		logger.Info("collector enabled", "collector", "network")
	}
	if cfg.Collector.Forensics.Enabled {
		fc, err := collector.NewForensicsCollector(cfg.Collector.Forensics, agentID, hostname, logger)
		if err != nil {
			logger.Error("failed to create forensics collector", "err", err)
		} else {
			collectors = append(collectors, fc)
			logger.Info("collector enabled", "collector", "forensics")
			defer func() {
				if err := fc.Close(); err != nil {
					logger.Warn("forensics collector close", "err", err)
				}
			}()
		}
	}
	if cfg.Collector.WebServer.Enabled {
		collectors = append(collectors,
			collector.NewWebServerCollector(cfg.Collector.WebServer, agentID, hostname, logger))
		logger.Info("collector enabled", "collector", "webserver")
	}

	// ── Agent ────────────────────────────────────────────────────────────────
	a := agent.New(agent.Config{
		ID:            agentID,
		FlushInterval: cfg.Agent.FlushInterval,
		Collectors:    collectors,
		Producer:      producer,
		SIEMAdapters:  adapters,
		Logger:        logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func buildLogger(cfg config.LoggingConfig) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}
