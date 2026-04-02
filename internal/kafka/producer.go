// Package kafka provides a Kafka producer for publishing AICyberSlayer events
// to a configured Kafka topic.
package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/davidlislc/AICyberSlayer/internal/config"
	"github.com/davidlislc/AICyberSlayer/pkg/event"
)

// Producer publishes events to a Kafka topic.
type Producer struct {
	writer *kafka.Writer
	logger *slog.Logger
}

// NewProducer creates and configures a Kafka producer from the supplied config.
func NewProducer(cfg config.KafkaConfig, logger *slog.Logger) (*Producer, error) {
	transport, err := buildTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("kafka: build transport: %w", err)
	}

	batchTimeout := time.Duration(cfg.WriteTimeoutSecs) * time.Second
	if batchTimeout <= 0 {
		batchTimeout = 10 * time.Second
	}

	w := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    cfg.BatchSize,
		WriteTimeout: batchTimeout,
		Transport:    transport,
		// Enable automatic topic creation if the broker allows it.
		AllowAutoTopicCreation: true,
	}

	return &Producer{writer: w, logger: logger}, nil
}

// Publish serialises the events to JSON and writes them to Kafka.
// The agentID is used as the message key so that events from the same agent
// end up in the same partition (ordered delivery).
func (p *Producer) Publish(ctx context.Context, agentID string, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}

	msgs := make([]kafka.Message, 0, len(events))
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			p.logger.Warn("kafka: marshal event", "id", e.ID, "err", err)
			continue
		}
		msgs = append(msgs, kafka.Message{
			Key:   []byte(agentID),
			Value: b,
		})
	}

	if len(msgs) == 0 {
		return nil
	}

	if err := p.writer.WriteMessages(ctx, msgs...); err != nil {
		return fmt.Errorf("kafka: write messages: %w", err)
	}
	p.logger.Debug("kafka: published events", "count", len(msgs), "topic", p.writer.Topic)
	return nil
}

// Close flushes pending writes and releases resources.
func (p *Producer) Close() error {
	return p.writer.Close()
}

// buildTransport constructs a kafka.Transport with optional TLS and SASL.
func buildTransport(cfg config.KafkaConfig) (*kafka.Transport, error) {
	t := &kafka.Transport{
		DialTimeout: 10 * time.Second,
	}

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLS(cfg.TLS)
		if err != nil {
			return nil, err
		}
		t.TLS = tlsCfg
	}

	if cfg.SASL.Enabled {
		mech, err := buildSASL(cfg.SASL)
		if err != nil {
			return nil, err
		}
		t.SASL = mech
	}

	return t, nil
}

func buildTLS(cfg config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.CAFile != "" {
		caPem, err := os.ReadFile(cfg.CAFile) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("tls: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPem) {
			return nil, fmt.Errorf("tls: parse CA certificate")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

func buildSASL(cfg config.SASLConfig) (sasl.Mechanism, error) {
	switch cfg.Mechanism {
	case "PLAIN", "plain", "":
		return plain.Mechanism{
			Username: cfg.Username,
			Password: cfg.Password,
		}, nil
	case "SCRAM-SHA-256":
		return scram.Mechanism(scram.SHA256, cfg.Username, cfg.Password)
	case "SCRAM-SHA-512":
		return scram.Mechanism(scram.SHA512, cfg.Username, cfg.Password)
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %q", cfg.Mechanism)
	}
}
