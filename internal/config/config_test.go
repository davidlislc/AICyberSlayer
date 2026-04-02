package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/davidlislc/AICyberSlayer/internal/config"
)

const minimalConfig = `
agent:
  flush_interval: 10s
kafka:
  brokers:
    - "localhost:9092"
  topic: "test-topic"
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "agent-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoadMinimalConfig(t *testing.T) {
	path := writeTempConfig(t, minimalConfig)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Kafka.Brokers) != 1 || cfg.Kafka.Brokers[0] != "localhost:9092" {
		t.Errorf("unexpected brokers: %v", cfg.Kafka.Brokers)
	}
	if cfg.Kafka.Topic != "test-topic" {
		t.Errorf("topic: got %q want %q", cfg.Kafka.Topic, "test-topic")
	}
}

func TestLoadMissingBrokersReturnsError(t *testing.T) {
	content := `
agent:
  flush_interval: 10s
kafka:
  topic: "test-topic"
`
	path := writeTempConfig(t, content)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing brokers, got nil")
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestEnvOverrides(t *testing.T) {
	path := writeTempConfig(t, minimalConfig)

	t.Setenv("KAFKA_SASL_PASSWORD", "sekret")
	t.Setenv("SPLUNK_HEC_TOKEN", "splunk-token")
	t.Setenv("ELASTIC_PASSWORD", "elastic-pass")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Kafka.SASL.Password != "sekret" {
		t.Errorf("KAFKA_SASL_PASSWORD not applied: got %q", cfg.Kafka.SASL.Password)
	}
	if cfg.SIEM.Splunk.Token != "splunk-token" {
		t.Errorf("SPLUNK_HEC_TOKEN not applied: got %q", cfg.SIEM.Splunk.Token)
	}
	if cfg.SIEM.Elastic.Password != "elastic-pass" {
		t.Errorf("ELASTIC_PASSWORD not applied: got %q", cfg.SIEM.Elastic.Password)
	}
}

func TestDefaults(t *testing.T) {
	path := writeTempConfig(t, minimalConfig)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Collector.System.Enabled {
		t.Error("system collector should be enabled by default")
	}
	if !cfg.Collector.Network.Enabled {
		t.Error("network collector should be enabled by default")
	}
	if cfg.Collector.WebServer.Enabled {
		t.Error("webserver collector should be disabled by default")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("default logging format: got %q want %q", cfg.Logging.Format, "json")
	}
}
