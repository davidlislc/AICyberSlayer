# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /aicyberslayer-agent ./cmd/agent

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM alpine:3.21

# Install ca-certificates so TLS to Kafka/SIEM endpoints works.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /aicyberslayer-agent /usr/local/bin/aicyberslayer-agent
COPY config/agent.yaml /etc/aicyberslayer/agent.yaml

# Expose no ports – agent is outbound only.
ENTRYPOINT ["/usr/local/bin/aicyberslayer-agent"]
CMD ["--config", "/etc/aicyberslayer/agent.yaml"]
