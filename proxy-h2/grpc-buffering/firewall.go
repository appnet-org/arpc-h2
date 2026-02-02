package main

import (
	"context"

	"github.com/appnet-org/arpc/pkg/logging"
	"go.uber.org/zap"
)

// FirewallElement is a demo element that logs and always passes traffic.
type FirewallElement struct{}

func (e *FirewallElement) Name() string { return "firewall-element" }

func (e *FirewallElement) ProcessRequest(ctx context.Context, rpcCtx *GRPCContext) (Verdict, context.Context, error) {
	if rpcCtx != nil {
		logging.Debug("Firewall element: request",
			zap.String("method", rpcCtx.Method),
			zap.String("remote", rpcCtx.RemoteAddr),
			zap.Int("payload_size", len(rpcCtx.Payload)),
		)
	}
	return VerdictPass, ctx, nil
}

func (e *FirewallElement) ProcessResponse(ctx context.Context, rpcCtx *GRPCContext) (Verdict, context.Context, error) {
	if rpcCtx != nil {
		logging.Debug("Firewall element: response",
			zap.String("method", rpcCtx.Method),
			zap.String("remote", rpcCtx.RemoteAddr),
			zap.Int("payload_size", len(rpcCtx.Payload)),
		)
	}
	return VerdictPass, ctx, nil
}
