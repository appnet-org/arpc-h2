package main

import (
	"context"
	"strings"
)

// Headers represents gRPC metadata headers as a map from header name to values.
// Header names are stored in lowercase.
type Headers map[string][]string

// GRPCContext contains the context for a gRPC message.
// This is a lightweight version tailored to grpc-buffering.
type GRPCContext struct {
	Headers    Headers
	Payload    []byte
	IsRequest  bool
	RemoteAddr string
	Method     string
}

// GetHeader returns the first value of a header, or empty string if not found.
func (c *GRPCContext) GetHeader(name string) string {
	values := c.Headers[strings.ToLower(name)]
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// SetHeader sets a header value (replaces existing values).
func (c *GRPCContext) SetHeader(name, value string) {
	c.Headers[strings.ToLower(name)] = []string{value}
}

// AddHeader adds a header value (appends to existing values).
func (c *GRPCContext) AddHeader(name, value string) {
	name = strings.ToLower(name)
	c.Headers[name] = append(c.Headers[name], value)
}

// RemoveHeader removes a header.
func (c *GRPCContext) RemoveHeader(name string) {
	delete(c.Headers, strings.ToLower(name))
}

// Verdict determines how the proxy should handle the RPC after processing.
type Verdict int

const (
	// VerdictPass allows the RPC to continue processing (forward normally).
	VerdictPass Verdict = iota
	// VerdictDrop drops the RPC (do not forward).
	VerdictDrop
)

// RPCElement defines the interface for gRPC elements.
type RPCElement interface {
	ProcessRequest(ctx context.Context, rpcCtx *GRPCContext) (Verdict, context.Context, error)
	ProcessResponse(ctx context.Context, rpcCtx *GRPCContext) (Verdict, context.Context, error)
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
func (c *RPCElementChain) ProcessRequest(ctx context.Context, rpcCtx *GRPCContext) (Verdict, context.Context, error) {
	var err error
	var verdict Verdict

	for _, element := range c.elements {
		verdict, ctx, err = element.ProcessRequest(ctx, rpcCtx)
		if err != nil {
			return VerdictPass, ctx, err
		}
		if verdict == VerdictDrop {
			return VerdictDrop, ctx, nil
		}
	}

	return VerdictPass, ctx, nil
}

// ProcessResponse processes the response through all RPC elements in reverse order.
func (c *RPCElementChain) ProcessResponse(ctx context.Context, rpcCtx *GRPCContext) (Verdict, context.Context, error) {
	var err error
	var verdict Verdict

	for i := len(c.elements) - 1; i >= 0; i-- {
		verdict, ctx, err = c.elements[i].ProcessResponse(ctx, rpcCtx)
		if err != nil {
			return VerdictPass, ctx, err
		}
		if verdict == VerdictDrop {
			return VerdictDrop, ctx, nil
		}
	}

	return VerdictPass, ctx, nil
}
