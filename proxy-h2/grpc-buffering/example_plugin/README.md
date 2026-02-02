# Example Element Plugin (grpc-buffering)

This directory contains an example element plugin that demonstrates how to create a dynamically loadable element for the proxy.

## Building the Plugin

### Quick Build (Recommended)

Use the provided build script, which automatically generates a timestamped filename:

```bash
cd /users/aruj/arpc-h2/proxy-h2/grpc-buffering/example_plugin
chmod +x build.sh
./build.sh
```

This will create a file like `element-20240115-143022.so` (timestamp format: YYYYMMDD-HHMMSS).

The timestamp ensures that newer builds are automatically selected by the elementloader, which picks the **highest alphabetically sorted** file matching the `element-` prefix.

### Custom Build Name

You can also specify a custom name:

```bash
./build.sh element-example-v2.so
```

### Manual Build

To build this plugin as a `.so` file manually:

```bash
cd /users/aruj/arpc-h2/proxy-h2
go build -buildmode=plugin -o grpc-buffering/example_plugin/element-demo.so grpc-buffering/example_plugin/example_element.go
```

**Important Notes:**
1. The plugin must be built with the same Go version as the main proxy binary
2. The plugin must use the same module dependencies (same `go.mod`)
3. The compiled `.so` file must be placed in `/appnet/arpc-plugins/` directory
4. The filename must start with `element-` prefix (e.g., `element-0001.so`, `element-20240115-143022.so`)
5. **File Selection**: The elementloader selects the **highest alphabetically sorted** file. Using timestamps (like `element-20240115-143022.so`) ensures newer builds are automatically selected.
6. **Toolchain**: `proxy-h2/go.mod` pins `toolchain go1.24.0`. The build script uses `GOTOOLCHAIN=local` to avoid auto-downloaded toolchains.
7. **Type Sharing**: This example imports shared types from `github.com/appnet-org/proxy-h2/grpc-buffering/util`.

## Plugin Requirements

1. **Package**: Must be `package main`
2. **Exported Symbol**: Must export a variable named `ElementInit` that implements the `elementInit` interface:
   ```go
   type elementInit interface {
       Element() RPCElement
       Init()
       Kill()
   }
   ```
3. **RPCElement Interface**: The element must implement:
   ```go
   type RPCElement interface {
       ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error)
       ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error)
       Name() string
   }
   ```

## Loading the Plugin

1. Copy the compiled `.so` file to `/appnet/arpc-plugins/`:
   ```bash
   sudo mkdir -p /appnet/arpc-plugins
   sudo cp element-*.so /appnet/arpc-plugins/
   ```

2. The proxy will automatically detect and load the plugin within 1 second

3. **File Selection**: The proxy loads the **highest alphabetically sorted** file matching the `element-` prefix:
   - `element-0001.so` < `element-0002.so`
   - `element-20240115-143022.so` < `element-20240115-150000.so` (newer timestamp = higher)
   - To update, place a new file with a higher alphabetical name (timestamped builds do this automatically)

## Example: Creating a Custom Element

Here's a template for creating your own element:

```go
package main

import (
    "context"
    "github.com/appnet-org/proxy-h2/grpc-buffering/util"
)

type MyCustomElement struct {
    // Your fields here
}

func (e *MyCustomElement) ProcessRequest(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
    // Your request processing logic
    return util.VerdictPass, ctx, nil
}

func (e *MyCustomElement) ProcessResponse(ctx context.Context, rpcCtx *util.GRPCContext) (util.Verdict, context.Context, error) {
    // Your response processing logic
    return util.VerdictPass, ctx, nil
}

func (e *MyCustomElement) Name() string {
    return "MyCustomElement"
}

type MyCustomElementInit struct {
    element *MyCustomElement
}

func (e *MyCustomElementInit) Element() RPCElement { return e.element }
func (e *MyCustomElementInit) Init()               {}
func (e *MyCustomElementInit) Kill()               {}

var ElementInit = &MyCustomElementInit{
    element: &MyCustomElement{},
}
```

## Troubleshooting

- **Plugin not loading**: Check that the file is in `/appnet/arpc-plugins/` and starts with `element-`
- **Type errors**: Ensure the plugin uses the same module version and Go version as the proxy
- **Symbol not found**: Make sure you export a variable named exactly `ElementInit`
- **Version mismatch**: Rebuild both the proxy and plugin with the same Go version

