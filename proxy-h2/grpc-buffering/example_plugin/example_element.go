// This is an example element plugin that can be compiled as a dynamically loadable .so file
// To build: go build -buildmode=plugin -o element-example.so example_element.go
//
// The compiled .so file should be placed in /appnet/elements/ with a name like:
// element-example.so, element-example-v2.so, etc. (the highest alphabetically sorted
// file matching the "element-" prefix will be loaded)

package main

import (
	"context"

	"github.com/appnet-org/arpc/pkg/logging"
	"github.com/appnet-org/proxy-h2/grpc-buffering/util"
	"go.uber.org/zap"
)

// ExampleElement is a simple example element that logs requests and responses
type ExampleElement struct {
	name string
}

// ProcessRequest processes incoming requests.
func (e *ExampleElement) ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
	if rpcCtx == nil {
		return util.VerdictPass, ctx, nil
	}

	logging.Info("ExampleElement: Processing request",
		zap.String("method", rpcCtx.Method),
		zap.String("remote", rpcCtx.RemoteAddr),
		zap.Int("payloadSize", len(rpcCtx.Payload)))

	// Example: You can modify the payload here if needed.
	return util.VerdictPass, ctx, nil
}

// ProcessResponse processes outgoing responses.
func (e *ExampleElement) ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
	if rpcCtx == nil {
		return util.VerdictPass, ctx, nil
	}

	logging.Info("ExampleElement: Processing response",
		zap.String("method", rpcCtx.Method),
		zap.String("remote", rpcCtx.RemoteAddr),
		zap.Int("payloadSize", len(rpcCtx.Payload)))

	// Example: You can modify the payload here if needed.
	return util.VerdictPass, ctx, nil
}

// Name returns the name of this element
func (e *ExampleElement) Name() string {
	return e.name
}

// RPCElement is the interface that elements must implement.
// NOTE: This must match the interface used by grpc-buffering.
type RPCElement interface {
	ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error)
	ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error)
	Name() string
}

// ExampleElementInit implements the elementInit interface required by the plugin loader
type ExampleElementInit struct {
	element *ExampleElement
}

// Element returns the RPCElement instance as interface{}.
func (e *ExampleElementInit) Element() interface{} {
	return e.element
}

// Init is called when the plugin is loaded.
func (e *ExampleElementInit) Init() {}

// Kill is called when the plugin is being unloaded (optional cleanup)
func (e *ExampleElementInit) Kill() {
	// Cleanup any background goroutines or resources here
	// For this example, there's nothing to clean up
	logging.Info("ExampleElement: Plugin being unloaded, performing cleanup")
}

// ElementInit is the exported symbol that the plugin loader looks for
// This must be named exactly "ElementInit"
//
// IMPORTANT: Export as interface{} so that plugin.Lookup returns *interface{},
// which the elementloader can dereference to get the concrete type that
// implements Element() and Kill() methods.
var ElementInit interface{} = &ExampleElementInit{
	element: &ExampleElement{
		name: "ExampleElement",
	},
}
