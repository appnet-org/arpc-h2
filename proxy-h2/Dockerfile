# Set Go image (match go.mod: go 1.24.0)
FROM golang:1.24.0-bullseye AS builder

ENV CGO_ENABLED=0
ENV GO111MODULE=on

# Create workspace
WORKDIR /app

# Copy the entire repository to handle the replace directive
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY proxy-h2/ ./proxy-h2/

WORKDIR /app/proxy-h2

# Build TCP proxy (no CGO)
RUN CGO_ENABLED=0 go build -trimpath -o proxy main.go

# Build gRPC buffering proxy (CGO required for plugin loading)
RUN CGO_ENABLED=1 go build -trimpath -o grpc-buffering/proxy-grpc-buffering ./grpc-buffering

# Final image
FROM ubuntu:22.04

WORKDIR /app
COPY --from=builder /app/proxy-h2/proxy /app/proxy
COPY --from=builder /app/proxy-h2/grpc-buffering/proxy-grpc-buffering /app/proxy-grpc-buffering

# Plugin directory for element .so files (mount volume or copy plugins here)
RUN mkdir -p /appnet/arpc-plugins && chmod 755 /appnet/arpc-plugins

RUN chmod +x /app/proxy /app/proxy-grpc-buffering