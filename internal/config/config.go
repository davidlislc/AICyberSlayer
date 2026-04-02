// Package config loads and validates the agent configuration from a YAML file
// or environment variables.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	Kafka     KafkaConfig     `yaml:"kafka"`
	Collector CollectorConfig `yaml:"collector"`
	SIEM      SIEMConfig      `yaml:"siem"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// AgentConfig holds agent identity and operational settings.
type AgentConfig struct {
	// ID is a human-readable identifier for this agent instance.
	// If empty the hostname is used.
	ID string `yaml:"id"`
	// FlushInterval controls how often collected metrics are published.
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// KafkaConfig holds Kafka connection settings.
type KafkaConfig struct {
	// Brokers is a list of bootstrap broker addresses (host:port).
	Brokers []string `yaml:"brokers"`
	// Topic is the Kafka topic events are written to.
	Topic string `yaml:"topic"`
	// TLS enables TLS transport to the brokers.
	TLS TLSConfig `yaml:"tls"`
	// SASL configures SASL authentication.
	SASL SASLConfig `yaml:"sasl"`
	// BatchSize is the maximum number of messages per batch.
	BatchSize int `yaml:"batch_size"`
	// WriteTimeoutSecs is the write timeout in seconds.
	WriteTimeoutSecs int `yaml:"write_timeout_secs"`
}

// TLSConfig holds TLS material paths.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

// SASLConfig holds SASL credentials.
type SASLConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Mechanism string `yaml:"mechanism"` // PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
}

// CollectorConfig controls which collectors are active and their settings.
type CollectorConfig struct {
	System    SystemCollectorConfig    `yaml:"system"`
	Network   NetworkCollectorConfig   `yaml:"network"`
	Forensics ForensicsCollectorConfig `yaml:"forensics"`
	WebServer WebServerCollectorConfig `yaml:"webserver"`
}

// SystemCollectorConfig controls the system metrics collector.
type SystemCollectorConfig struct {
	Enabled bool `yaml:"enabled"`
	// CollectProcesses enables per-process collection (can be expensive).
	CollectProcesses bool `yaml:"collect_processes"`
}

// NetworkCollectorConfig controls the network collector.
type NetworkCollectorConfig struct {
	Enabled bool `yaml:"enabled"`
	// CollectConnections enables socket/connection table collection.
	CollectConnections bool `yaml:"collect_connections"`
}

// ForensicsCollectorConfig controls the forensics collector.
type ForensicsCollectorConfig struct {
	Enabled bool `yaml:"enabled"`
	// WatchPaths is the list of filesystem paths to monitor for changes.
	WatchPaths []string `yaml:"watch_paths"`
	// CollectLogins enables reading of auth/login logs.
	CollectLogins bool `yaml:"collect_logins"`
}

// WebServerCollectorConfig controls the web server log collector.
type WebServerCollectorConfig struct {
	Enabled bool `yaml:"enabled"`
	// LogFiles are the access log file paths to tail.
	LogFiles []string `yaml:"log_files"`
	// Format is the log format: "combined" (default) or "common".
	Format string `yaml:"format"`
}

// SIEMConfig configures optional SIEM output adapters.
type SIEMConfig struct {
	Splunk     SplunkConfig     `yaml:"splunk"`
	Elastic    ElasticConfig    `yaml:"elastic"`
	SyslogSIEM SyslogSIEMConfig `yaml:"syslog"`
}

// SplunkConfig holds Splunk HEC settings.
type SplunkConfig struct {
	Enabled  bool   `yaml:"enabled"`
	HECURL   string `yaml:"hec_url"`
	Token    string `yaml:"token"`
	Index    string `yaml:"index"`
	Insecure bool   `yaml:"insecure"`
}

// ElasticConfig holds Elasticsearch / Elastic SIEM settings.
type ElasticConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Addresses []string `yaml:"addresses"`
	Index     string   `yaml:"index"`
	Username  string   `yaml:"username"`
	Password  string   `yaml:"password"`
	Insecure  bool     `yaml:"insecure"`
}

// SyslogSIEMConfig holds generic syslog/CEF forwarding settings.
type SyslogSIEMConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Network  string `yaml:"network"`  // tcp | udp
	Address  string `yaml:"address"`  // host:port
	Protocol string `yaml:"protocol"` // syslog | cef
}

// LoggingConfig controls the agent's own log output.
type LoggingConfig struct {
	// Level is the minimum log level: debug, info, warn, error.
	Level string `yaml:"level"`
	// Format is "json" or "text".
	Format string `yaml:"format"`
}

// Load reads configuration from the file at path.
// Environment variable overrides are applied after parsing.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 - path is supplied by the operator
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	cfg := defaults()
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: decode %q: %w", path, err)
	}
	applyEnvOverrides(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaults returns a Config populated with sensible defaults.
func defaults() *Config {
	return &Config{
		Agent: AgentConfig{
			FlushInterval: 30 * time.Second,
		},
		Kafka: KafkaConfig{
			Topic:            "aicyberslayer",
			BatchSize:        100,
			WriteTimeoutSecs: 10,
		},
		Collector: CollectorConfig{
			System: SystemCollectorConfig{
				Enabled:          true,
				CollectProcesses: true,
			},
			Network: NetworkCollectorConfig{
				Enabled:            true,
				CollectConnections: true,
			},
			Forensics: ForensicsCollectorConfig{
				Enabled:       true,
				CollectLogins: true,
			},
			WebServer: WebServerCollectorConfig{
				Enabled: false,
				Format:  "combined",
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// applyEnvOverrides overrides sensitive fields from environment variables.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("KAFKA_SASL_PASSWORD"); v != "" {
		cfg.Kafka.SASL.Password = v
	}
	if v := os.Getenv("SPLUNK_HEC_TOKEN"); v != "" {
		cfg.SIEM.Splunk.Token = v
	}
	if v := os.Getenv("ELASTIC_PASSWORD"); v != "" {
		cfg.SIEM.Elastic.Password = v
	}
}

// validate checks required fields.
func validate(cfg *Config) error {
	if len(cfg.Kafka.Brokers) == 0 {
		return fmt.Errorf("config: kafka.brokers must not be empty")
	}
	if cfg.Agent.FlushInterval <= 0 {
		return fmt.Errorf("config: agent.flush_interval must be positive")
	}
	return nil
}
