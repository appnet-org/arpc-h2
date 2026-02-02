package main

import (
	"context"

	"github.com/appnet-org/proxy-h2/grpc-buffering/util"
)

// RPCElement defines the interface for gRPC elements.
type RPCElement interface {
	ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error)
	ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error)
	Name() string
}

// RPCElementChain represents a chain of RPC elements.
type RPCElementChain struct {
	elements []RPCElement
}

// NewRPCElementChain creates a new chain of RPC elements.
func NewRPCElementChain(elements ...RPCElement) *RPCElementChain {
	return &RPCElementChain{
		elements: elements,
	}
}

// ProcessRequest processes the request through all RPC elements in the chain.
func (c *RPCElementChain) ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
	var err error
	var verdict util.Verdict

	for _, element := range c.elements {
		verdict, ctx, err = element.ProcessRequest(ctx, rpcCtx)
		if err != nil {
			return util.VerdictPass, ctx, err
		}
		if verdict == util.VerdictDrop {
			return util.VerdictDrop, ctx, nil
		}
	}

	return util.VerdictPass, ctx, nil
}

// ProcessResponse processes the response through all RPC elements in reverse order.
func (c *RPCElementChain) ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
	var err error
	var verdict util.Verdict

	for i := len(c.elements) - 1; i >= 0; i-- {
		verdict, ctx, err = c.elements[i].ProcessResponse(ctx, rpcCtx)
		if err != nil {
			return util.VerdictPass, ctx, err
		}
		if verdict == util.VerdictDrop {
			return util.VerdictDrop, ctx, nil
		}
	}

	return util.VerdictPass, ctx, nil
}
