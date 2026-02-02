// This is an example element plugin that can be compiled as a dynamically loadable .so file
// To build: go build -buildmode=plugin -o element-example.so example_element.go
//
// The compiled .so file should be placed in /appnet/elements/ with a name like:
// element-example.so, element-example-v2.so, etc. (the highest alphabetically sorted
// file matching the "element-" prefix will be loaded)

package main

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/appnet-org/arpc/pkg/logging"
	"github.com/appnet-org/proxy-h2/grpc-buffering/util"
	"go.uber.org/zap"
)

// ExampleElement is a simple example element that logs requests/responses
// and drops each request with 50% probability.
type ExampleElement struct {
	name string
	mu   sync.Mutex
	rng  *rand.Rand
}

// ProcessRequest processes incoming requests. Drops each request with 50% probability.
func (e *ExampleElement) ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
	if rpcCtx == nil {
		return util.VerdictPass, ctx, nil
	}

	e.mu.Lock()
	dropThis := e.rng.Float64() < 0.5
	e.mu.Unlock()

	if dropThis {
		logging.Info("ExampleElement: Dropping request (50% drop)",
			zap.String("method", rpcCtx.Method),
			zap.String("remote", rpcCtx.RemoteAddr),
			zap.Int("payloadSize", len(rpcCtx.Payload)))
		return util.VerdictDrop, ctx, nil
	}

	logging.Info("ExampleElement: Processing request",
		zap.String("method", rpcCtx.Method),
		zap.String("remote", rpcCtx.RemoteAddr),
		zap.Int("payloadSize", len(rpcCtx.Payload)))
	return util.VerdictPass, ctx, nil
}

// ProcessResponse processes outgoing responses (always pass).
func (e *ExampleElement) ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
	if rpcCtx == nil {
		return util.VerdictPass, ctx, nil
	}

	logging.Info("ExampleElement: Processing response",
		zap.String("method", rpcCtx.Method),
		zap.String("remote", rpcCtx.RemoteAddr),
		zap.Int("payloadSize", len(rpcCtx.Payload)))
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

// Init is called when the plugin is loaded. Seeds RNG for 50% drop probability.
func (e *ExampleElementInit) Init() {
	e.element.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	logging.Info("ExampleElement: init, 50% drop probability for requests")
}

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
