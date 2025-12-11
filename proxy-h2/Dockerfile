# Set Go image
FROM golang:1.24.0-bullseye AS builder

ENV CGO_ENABLED=0
ENV GO111MODULE=on

# Create workspace
WORKDIR /app

# Copy the entire repository to handle the replace directive
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY proxy-h2/ ./proxy-h2/

# Build from the proxy-h2 directory
WORKDIR /app/proxy-h2
RUN go build -o proxy main.go
# Build gRPC buffering from its own directory
WORKDIR /app/proxy-h2/grpc-buffering
RUN go build -o proxy-grpc-buffering main.go

# Final image
FROM ubuntu:22.04

WORKDIR /app
COPY --from=builder /app/proxy-h2/proxy /app/proxy
COPY --from=builder /app/proxy-h2/grpc-buffering/proxy-grpc-buffering /app/proxy-grpc-buffering

RUN chmod +x /app/proxy /app/proxy-grpc-buffering