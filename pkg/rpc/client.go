// pkg/rpc/client.go
package rpc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/appnet-org/arpc-h2/pkg/logging"
	"github.com/appnet-org/arpc-h2/pkg/packet"
	"github.com/appnet-org/arpc-h2/pkg/rpc/element"
	"github.com/appnet-org/arpc-h2/pkg/serializer"
	"github.com/appnet-org/arpc-h2/pkg/transport"
	"go.uber.org/zap"
)

// Client represents an RPC client with a transport and serializer.
type Client struct {
	transport       *transport.HTTP2Transport
	serializer      serializer.Serializer
	defaultAddr     string
	rpcElementChain *element.RPCElementChain
	streamingMode   bool
}

// NewClient creates a new Client using the given serializer and target address.
// The client will create an HTTP/2 connection to the server.
func NewClient(serializer serializer.Serializer, addr string, rpcElements ...element.RPCElement) (*Client, error) {
	t, err := transport.NewHTTP2ClientTransport()
	if err != nil {
		return nil, err
	}
	return &Client{
		transport:       t,
		serializer:      serializer,
		defaultAddr:     addr,
		rpcElementChain: element.NewRPCElementChain(rpcElements...),
	}, nil
}

// NewClientWithLocalAddr creates a new Client using the given serializer, target address, and local address.
// Note: For HTTP/2, the local address is not used in the same way as UDP.
// This function is kept for API compatibility but the localAddr parameter is ignored.
func NewClientWithLocalAddr(serializer serializer.Serializer, addr, localAddr string, rpcElements ...element.RPCElement) (*Client, error) {
	// For HTTP/2, we don't bind to a local address in the same way
	// The OS will assign a local port when we connect
	return NewClient(serializer, addr, rpcElements...)
}

// Transport returns the underlying HTTP/2 transport for cleanup purposes
func (c *Client) Transport() *transport.HTTP2Transport {
	return c.transport
}

// EnableStreaming enables streaming mode for the client
// In streaming mode, all RPCs are sent over a persistent HTTP/2 stream
// which reduces per-RPC overhead significantly
func (c *Client) EnableStreaming() error {
	if err := c.transport.EnableStreaming(c.defaultAddr); err != nil {
		return fmt.Errorf("failed to enable streaming: %w", err)
	}
	c.streamingMode = true
	return nil
}

// IsStreamingEnabled returns whether streaming mode is enabled
func (c *Client) IsStreamingEnabled() bool {
	return c.streamingMode && c.transport.IsStreamingEnabled()
}

// frameRequest constructs a binary message with
// [serviceLen(2B)][service][methodLen(2B)][method][payload]
func (c *Client) frameRequest(service, method string, payload []byte) ([]byte, error) {
	// Pre-calculate buffer size (headers: 2 + 2 = 4 bytes)
	totalSize := 4 + len(service) + len(method) + len(payload)
	buf := make([]byte, totalSize)

	// service
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(service)))
	copy(buf[2:], service)

	// method
	methodStart := 2 + len(service)
	binary.LittleEndian.PutUint16(buf[methodStart:methodStart+2], uint16(len(method)))
	copy(buf[methodStart+2:], method)

	// payload
	payloadStart := methodStart + 2 + len(method)
	copy(buf[payloadStart:], payload)

	return buf, nil
}

func (c *Client) parseFramedResponse(data []byte) (service string, method string, payload []byte, err error) {
	offset := 0

	// Parse service name
	if len(data) < 2 {
		return "", "", nil, fmt.Errorf("invalid response (too short for serviceLen)")
	}
	serviceLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+serviceLen > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (truncated service)")
	}
	service = string(data[offset : offset+serviceLen])
	offset += serviceLen

	// Parse method name
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (too short for methodLen)")
	}
	methodLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+methodLen > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (truncated method)")
	}
	method = string(data[offset : offset+methodLen])
	offset += methodLen

	payload = data[offset:]
	return service, method, payload, nil
}

func (c *Client) handleErrorPacket(ctx context.Context, errMsg string, errType packet.PacketTypeID) error {
	// Create error response for RPC element processing
	rpcResp := &element.RPCResponse{
		Result: nil,
		Error:  fmt.Errorf("server error: %s", errMsg),
	}

	// Process error response through RPC elements
	_, _, err := c.rpcElementChain.ProcessResponse(ctx, rpcResp)
	if err != nil {
		return err
	}

	var rpcErrType RPCErrorType
	if errType == packet.PacketTypeError {
		rpcErrType = RPCFailError
	} else {
		rpcErrType = RPCUnknownError
	}
	return &RPCError{Type: rpcErrType, Reason: errMsg}
}

func (c *Client) handleResponsePacket(ctx context.Context, data []byte, rpcID uint64, resp any) error {
	// Parse framed response: extract service, method, payload
	_, _, respPayloadBytes, err := c.parseFramedResponse(data)
	if err != nil {
		return fmt.Errorf("failed to parse framed response: %w", err)
	}

	// Deserialize the response into resp
	if err := c.serializer.Unmarshal(respPayloadBytes, resp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	logging.Debug("Successfully received response", zap.Uint64("rpcID", rpcID))

	// Create response for RPC element processing
	rpcResp := &element.RPCResponse{
		ID:     rpcID,
		Result: resp,
		Error:  nil,
	}

	// Process response through RPC elements
	rpcResp, ctx, err = c.rpcElementChain.ProcessResponse(ctx, rpcResp)
	if err != nil {
		return err
	}

	return rpcResp.Error
}

// Call makes an RPC call with RPC element processing
func (c *Client) Call(ctx context.Context, service, method string, req any, resp any) error {
	rpcReqID := transport.GenerateRPCID()

	// Create request with service and method information
	rpcReq := &element.RPCRequest{
		ServiceName: service,
		Method:      method,
		ID:          rpcReqID,
		Payload:     req,
	}

	// Process request through RPC elements
	rpcReq, ctx, err := c.rpcElementChain.ProcessRequest(ctx, rpcReq)
	if err != nil {
		return err
	}

	// Serialize the request payload
	reqPayloadBytes, err := c.serializer.Marshal(rpcReq.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Frame the request into binary format
	framedReq, err := c.frameRequest(rpcReq.ServiceName, rpcReq.Method, reqPayloadBytes)
	if err != nil {
		return fmt.Errorf("failed to frame request: %w", err)
	}

	// Register for response before sending (to avoid race condition)
	responseChan := c.transport.GetDispatcher().Register(rpcReq.ID)
	defer c.transport.GetDispatcher().Unregister(rpcReq.ID)

	// Send the framed request (use streaming if enabled)
	if c.IsStreamingEnabled() {
		if err := c.transport.SendStreaming(rpcReq.ID, framedReq, packet.PacketTypeData); err != nil {
			return fmt.Errorf("failed to send streaming request: %w", err)
		}
	} else {
		if err := c.transport.Send(c.defaultAddr, rpcReq.ID, framedReq, packet.PacketTypeData); err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
	}

	// Wait for response
	select {
	case respData := <-responseChan:
		if respData == nil {
			return fmt.Errorf("response channel closed")
		}
		if respData.Err != nil {
			return respData.Err
		}

		data := respData.Data
		respID := respData.RPCID
		packetTypeID := respData.PacketType

		if data == nil {
			return fmt.Errorf("received nil data for RPC ID %d", rpcReqID)
		}

		// Process the packet based on its type
		switch packetTypeID {
		case packet.PacketTypeData:
			return c.handleResponsePacket(ctx, data, respID, resp)
		case packet.PacketTypeError, packet.PacketTypeUnknown:
			return c.handleErrorPacket(ctx, string(data), packetTypeID)
		default:
			return fmt.Errorf("unknown packet type: %d", packetTypeID)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetTransport returns the underlying transport for advanced operations
func (c *Client) GetTransport() *transport.HTTP2Transport {
	return c.transport
}
