package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/appnet-org/arpc-h2/pkg/packet"
	"github.com/appnet-org/arpc-h2/pkg/transport/balancer"
	"github.com/appnet-org/arpc/pkg/logging"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// GenerateRPCID creates a unique RPC ID
func GenerateRPCID() uint64 {
	return uint64(time.Now().UnixNano())
}

// responseDispatcher manages response routing by RPC ID
// Optimized for high-concurrency scenarios with sync.Map for better performance
type responseDispatcher struct {
	responses   sync.Map // map[uint64]chan *responseData - using sync.Map for better concurrent performance
	pendingData sync.Map // map[uint64]*responseData - store responses that arrive before registration
}

type responseData struct {
	data       []byte
	addr       *net.TCPAddr
	rpcID      uint64
	packetType packet.PacketTypeID
	err        error
}

func newResponseDispatcher() *responseDispatcher {
	return &responseDispatcher{}
}

func (d *responseDispatcher) register(rpcID uint64) chan *responseData {
	ch := make(chan *responseData, 1)
	d.responses.Store(rpcID, ch)

	// Check if there's pending data for this RPC ID (common case: no pending data)
	if pending, exists := d.pendingData.LoadAndDelete(rpcID); exists {
		// Send the pending data immediately (non-blocking)
		select {
		case ch <- pending.(*responseData):
		default:
			// Channel is full, this shouldn't happen with buffered channel
			logging.Debug("Failed to send pending data to channel", zap.Uint64("rpcID", rpcID))
		}
	}

	return ch
}

func (d *responseDispatcher) unregister(rpcID uint64) {
	if chVal, exists := d.responses.LoadAndDelete(rpcID); exists {
		ch := chVal.(chan *responseData)
		close(ch)
	}
	// Also clean up any pending data
	d.pendingData.Delete(rpcID)
}

// ResponseData is a public wrapper for response data
type ResponseData struct {
	Data       []byte
	Addr       *net.TCPAddr
	RPCID      uint64
	PacketType packet.PacketTypeID
	Err        error
}

// ResponseDispatcher is a public interface for the response dispatcher
type ResponseDispatcher struct {
	d *responseDispatcher
}

// Register registers for responses for a given RPC ID
func (rd *ResponseDispatcher) Register(rpcID uint64) <-chan *ResponseData {
	internalCh := rd.d.register(rpcID)
	// Create a channel that wraps the internal channel
	ch := make(chan *ResponseData, 1)
	go func() {
		resp := <-internalCh
		if resp == nil {
			close(ch)
			return
		}
		ch <- &ResponseData{
			Data:       resp.data,
			Addr:       resp.addr,
			RPCID:      resp.rpcID,
			PacketType: resp.packetType,
			Err:        resp.err,
		}
	}()
	return ch
}

// Unregister unregisters for responses for a given RPC ID
func (rd *ResponseDispatcher) Unregister(rpcID uint64) {
	rd.d.unregister(rpcID)
}

// dispatch routes a response to the appropriate channel based on RPC ID
// Optimized for the common case where the channel is already registered
func (d *responseDispatcher) dispatch(data []byte, addr *net.TCPAddr, rpcID uint64, packetType packet.PacketTypeID, err error) {
	respData := &responseData{
		data:       data,
		addr:       addr,
		rpcID:      rpcID,
		packetType: packetType,
		err:        err,
	}

	// Fast path: check if channel is registered (most common case)
	if chVal, exists := d.responses.Load(rpcID); exists {
		ch := chVal.(chan *responseData)
		// Non-blocking send to avoid goroutine blocking
		select {
		case ch <- respData:
			// Successfully dispatched
			return
		default:
			// Channel is full or closed (shouldn't happen with buffered channel)
			logging.Debug("Response channel full or closed for RPC ID", zap.Uint64("rpcID", rpcID))
		}
	}

	// Slow path: no one is registered yet, store the response for later
	d.pendingData.Store(rpcID, respData)
	logging.Debug("Storing response for later delivery", zap.Uint64("rpcID", rpcID))
}

type HTTP2Transport struct {
	server      *http.Server
	client      *http.Client
	reassembler *DataReassembler
	resolver    *balancer.Resolver
	isServer    bool
	handler     http.HandlerFunc
	streams     map[uint64]*streamContext
	streamMutex sync.RWMutex
	dispatcher  *responseDispatcher

	// Streaming client fields
	streamingMode   bool
	streamPipeW     *io.PipeWriter
	streamPipeR     *io.PipeReader
	streamAddr      string
	streamReaderWg  sync.WaitGroup
	streamConnected bool
	streamMu        sync.Mutex
}

type streamContext struct {
	dataChan   chan []byte
	addr       *net.TCPAddr
	rpcID      uint64
	packetType packet.PacketTypeID
	errChan    chan error
}

func NewHTTP2Transport(address string) (*HTTP2Transport, error) {
	return NewHTTP2TransportWithBalancer(address, balancer.DefaultResolver())
}

// NewHTTP2TransportWithBalancer creates a new HTTP/2 transport with a custom balancer
func NewHTTP2TransportWithBalancer(address string, resolver *balancer.Resolver) (*HTTP2Transport, error) {
	transport := &HTTP2Transport{
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
		streams:     make(map[uint64]*streamContext),
		handler:     nil,
		dispatcher:  newResponseDispatcher(),
	}

	mux := http.NewServeMux()

	// Configure HTTP/2 server (handler will be set by SetHandler)
	server := &http.Server{
		Addr:    address,
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	transport.server = server

	return transport, nil
}

func (t *HTTP2Transport) SetHandler(handler http.HandlerFunc) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	t.server.Handler = h2c.NewHandler(mux, &http2.Server{})
}

// SetHandlers sets both unary and stream handlers
func (t *HTTP2Transport) SetHandlers(unaryHandler, streamHandler http.HandlerFunc) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", unaryHandler)
	mux.HandleFunc("/stream", streamHandler)
	t.server.Handler = h2c.NewHandler(mux, &http2.Server{})
}

// NewHTTP2ClientTransport creates an HTTP/2 transport for client use
func NewHTTP2ClientTransport() (*HTTP2Transport, error) {
	// Configure HTTP/2 client
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
		Timeout: 30 * time.Second,
	}

	transport := &HTTP2Transport{
		client:      client,
		reassembler: NewDataReassembler(),
		resolver:    balancer.DefaultResolver(),
		isServer:    false,
		streams:     make(map[uint64]*streamContext),
		dispatcher:  newResponseDispatcher(),
	}

	return transport, nil
}

// NewHTTP2TransportForStream creates an HTTP/2 transport for a server stream
func NewHTTP2TransportForStream(resolver *balancer.Resolver) *HTTP2Transport {
	return &HTTP2Transport{
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
		streams:     make(map[uint64]*streamContext),
		dispatcher:  newResponseDispatcher(),
	}
}

// EnableStreaming enables streaming mode for the client transport
// This establishes a persistent HTTP/2 stream to the given address
func (t *HTTP2Transport) EnableStreaming(addr string) error {
	if t.isServer {
		return fmt.Errorf("EnableStreaming can only be called on a client transport")
	}

	t.streamMu.Lock()
	defer t.streamMu.Unlock()

	if t.streamConnected {
		return nil // Already connected
	}

	// Create pipe for sending data
	pipeR, pipeW := io.Pipe()
	t.streamPipeR = pipeR
	t.streamPipeW = pipeW
	t.streamAddr = addr
	t.streamingMode = true

	// Format URL
	url := addr
	if len(url) < 7 || url[:7] != "http://" {
		url = "http://" + url
	}
	url = url + "/stream"

	// Create the streaming request
	req, err := http.NewRequest("POST", url, pipeR)
	if err != nil {
		t.streamPipeW.Close()
		t.streamPipeR.Close()
		return fmt.Errorf("failed to create streaming request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	// Start the request in a goroutine
	t.streamReaderWg.Add(1)
	go func() {
		defer t.streamReaderWg.Done()
		t.runStreamingClient(req)
	}()

	t.streamConnected = true
	return nil
}

// runStreamingClient handles the streaming HTTP/2 connection
func (t *HTTP2Transport) runStreamingClient(req *http.Request) {
	resp, err := t.client.Do(req)
	if err != nil {
		logging.Error("Streaming connection failed", zap.Error(err))
		t.streamMu.Lock()
		t.streamConnected = false
		t.streamMu.Unlock()
		return
	}
	defer resp.Body.Close()

	// Read responses from the stream
	reader := NewStreamReader(resp.Body)
	for {
		result, err := reader.ReadAndProcessPacket(t, nil)
		if err != nil {
			if err == io.EOF {
				logging.Debug("Stream closed by server")
			} else {
				logging.Error("Error reading from stream", zap.Error(err))
			}
			break
		}

		if result.IsComplete {
			// Dispatch the response
			var pktType packet.PacketTypeID
			if result.IsError {
				pktType = packet.PacketTypeError
			} else {
				pktType = packet.PacketTypeData
			}
			t.dispatcher.dispatch(result.Data, result.Addr, result.RPCID, pktType, nil)
		}
	}

	t.streamMu.Lock()
	t.streamConnected = false
	t.streamMu.Unlock()
}

// SendStreaming sends data over the persistent stream (streaming mode only)
func (t *HTTP2Transport) SendStreaming(rpcID uint64, data []byte, packetTypeID packet.PacketTypeID) error {
	t.streamMu.Lock()
	if !t.streamingMode || !t.streamConnected {
		t.streamMu.Unlock()
		return fmt.Errorf("streaming mode not enabled or not connected")
	}
	pipeW := t.streamPipeW
	t.streamMu.Unlock()

	// Fragment and write to the pipe
	return FragmentAndWriteFrames(pipeW, t.reassembler, data, rpcID, packetTypeID)
}

// IsStreamingEnabled returns whether streaming mode is enabled
func (t *HTTP2Transport) IsStreamingEnabled() bool {
	t.streamMu.Lock()
	defer t.streamMu.Unlock()
	return t.streamingMode && t.streamConnected
}

func (t *HTTP2Transport) Send(addr string, rpcID uint64, data []byte, packetTypeID packet.PacketTypeID) error {
	if t.isServer {
		// Server mode: Send is not used directly in HTTP/2 server mode
		// The server handler writes responses directly to the HTTP response writer
		return fmt.Errorf("Send not supported in server mode, use HTTP response writer directly")
	} else {
		// Client mode: send HTTP/2 request
		// Ensure URL is properly formatted
		if addr == "" {
			return fmt.Errorf("address cannot be empty")
		}

		// Add http:// prefix if not present
		url := addr
		if len(url) < 7 || url[:7] != "http://" {
			url = "http://" + url
		}

		// Extract destination IP and port from URL (for fragmentation header)
		var dstIP [4]byte
		var dstPort uint16
		var srcIP [4]byte
		var srcPort uint16

		// Fragment the data into multiple packets if needed
		packets, err := t.reassembler.FragmentData(data, rpcID, packetTypeID, dstIP, dstPort, srcIP, srcPort)
		if err != nil {
			return err
		}

		// Serialize all packets into a single request body
		var requestData bytes.Buffer
		lenBuf := lenBufPool.Get().([]byte)
		defer lenBufPool.Put(lenBuf)

		for _, pkt := range packets {
			var packetData []byte
			switch p := pkt.(type) {
			case *packet.DataPacket:
				packetData, err = packet.SerializeDataPacket(p)
			case *packet.ErrorPacket:
				packetData, err = packet.SerializeErrorPacket(p)
			default:
				return fmt.Errorf("unknown packet type: %T", pkt)
			}

			if err != nil {
				return fmt.Errorf("failed to serialize packet: %w", err)
			}

			// Write packet length first (4 bytes) for framing
			binary.LittleEndian.PutUint32(lenBuf, uint32(len(packetData)))
			requestData.Write(lenBuf)
			requestData.Write(packetData)
		}

		// Create HTTP/2 request
		req, err := http.NewRequest("POST", url, &requestData)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		// Set headers
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-RPC-ID", fmt.Sprintf("%d", rpcID))

		// Send request
		resp, err := t.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		// Store response for receive
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		// Process the response and dispatch it
		// Check if channel is already registered (optimization: avoid goroutine if possible)
		if _, registered := t.dispatcher.responses.Load(rpcID); registered {
			// Channel is already registered, process synchronously for better performance
			// Process the received data
			data, addr, processedRPCID, pktType, processErr := t.ProcessReceivedData(respBody, nil, rpcID, packetTypeID, packet.MaxTCPPayloadSize)

			if processErr != nil {
				t.dispatcher.dispatch(nil, nil, rpcID, packet.PacketTypeUnknown, processErr)
				return nil
			}

			// Dispatch the response (may be nil if still waiting for fragments)
			if data != nil {
				t.dispatcher.dispatch(data, addr, processedRPCID, pktType, nil)
			} else {
				// If data is nil, it means we're still waiting for fragments
				// This shouldn't happen for HTTP/2 as all fragments should be in the response body
				// But if it does, we should dispatch an error
				t.dispatcher.dispatch(nil, nil, rpcID, packet.PacketTypeUnknown, fmt.Errorf("incomplete fragments received"))
			}
		} else {
			// Channel not registered yet, process in goroutine to avoid blocking Send()
			go func() {
				// Process the received data
				data, addr, processedRPCID, pktType, processErr := t.ProcessReceivedData(respBody, nil, rpcID, packetTypeID, packet.MaxTCPPayloadSize)

				if processErr != nil {
					t.dispatcher.dispatch(nil, nil, rpcID, packet.PacketTypeUnknown, processErr)
					return
				}

				// Dispatch the response (may be nil if still waiting for fragments)
				if data != nil {
					t.dispatcher.dispatch(data, addr, processedRPCID, pktType, nil)
				} else {
					// If data is nil, it means we're still waiting for fragments
					// This shouldn't happen for HTTP/2 as all fragments should be in the response body
					// But if it does, we should dispatch an error
					t.dispatcher.dispatch(nil, nil, rpcID, packet.PacketTypeUnknown, fmt.Errorf("incomplete fragments received"))
				}
			}()
		}

		return nil
	}
}

// ReceiveForRPC waits for a response for a specific RPC ID and returns the response data.
// This method should be used by clients to receive responses for specific RPC calls.
// It blocks until a response is received for the given RPC ID or an error occurs.
func (t *HTTP2Transport) ReceiveForRPC(ctx context.Context, rpcID uint64, bufferSize int) ([]byte, *net.TCPAddr, uint64, packet.PacketTypeID, error) {
	// Register for this specific RPC ID
	responseChan := t.dispatcher.register(rpcID)
	defer t.dispatcher.unregister(rpcID)

	// Wait for response
	select {
	case respData := <-responseChan:
		if respData == nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("response channel closed")
		}
		if respData.err != nil {
			return nil, nil, 0, packet.PacketTypeUnknown, respData.err
		}
		return respData.data, respData.addr, respData.rpcID, respData.packetType, nil
	case <-ctx.Done():
		return nil, nil, 0, packet.PacketTypeUnknown, ctx.Err()
	}
}

// Receive takes a buffer size as input, reads data from the HTTP/2 stream, and returns
// the following information when receiving the complete data for an RPC message:
// * complete data for a message (if no message is complete, it will return nil)
// * original source address from connection (for responses)
// * RPC id
// * packet type
// * error
// NOTE: This method is deprecated for client use. Use ReceiveForRPC instead for proper RPC ID matching.
func (t *HTTP2Transport) Receive(bufferSize int) ([]byte, *net.TCPAddr, uint64, packet.PacketTypeID, error) {
	// For server, we need to check if we have any completed streams
	if t.isServer {
		t.streamMutex.RLock()
		for rpcID, ctx := range t.streams {
			select {
			case data := <-ctx.dataChan:
				t.streamMutex.RUnlock()
				// Process the received data
				return t.ProcessReceivedData(data, ctx.addr, rpcID, ctx.packetType, bufferSize)
			default:
				// No data available for this stream, continue
			}
		}
		t.streamMutex.RUnlock()
		// No data available
		return nil, nil, 0, packet.PacketTypeUnknown, nil
	} else {
		// Client: check for response data
		t.streamMutex.RLock()
		for rpcID, ctx := range t.streams {
			select {
			case data := <-ctx.dataChan:
				t.streamMutex.RUnlock()
				// Process the received data
				return t.ProcessReceivedData(data, nil, rpcID, ctx.packetType, bufferSize)
			default:
				// No data available for this stream, continue
			}
		}
		t.streamMutex.RUnlock()
		// No data available
		return nil, nil, 0, packet.PacketTypeUnknown, nil
	}
}

// ProcessReceivedData processes received data and handles fragmentation
func (t *HTTP2Transport) ProcessReceivedData(data []byte, addr *net.TCPAddr, rpcID uint64, packetTypeID packet.PacketTypeID, bufferSize int) ([]byte, *net.TCPAddr, uint64, packet.PacketTypeID, error) {
	// Read packets from the data (they are framed with length prefixes)
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("data too short for packet length")
		}

		// Read packet length
		packetLen := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(packetLen) > len(data) {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("packet length %d exceeds remaining data", packetLen)
		}

		if packetLen > uint32(bufferSize) {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("packet length %d exceeds buffer size %d", packetLen, bufferSize)
		}

		// Read packet data
		packetData := data[offset : offset+int(packetLen)]
		offset += int(packetLen)

		// Deserialize packet
		pkt, pktType, err := packet.DeserializePacket(packetData)
		if err != nil {
			return nil, nil, 0, packet.PacketTypeUnknown, err
		}

		// Handle different packet types
		switch p := pkt.(type) {
		case *packet.DataPacket:
			// Process fragment through reassembly layer
			message, _, reassembledRPCID, isComplete := t.reassembler.ProcessFragment(p, addr)
			if isComplete {
				// Clean up stream context
				t.streamMutex.Lock()
				delete(t.streams, rpcID)
				t.streamMutex.Unlock()
				return message, addr, reassembledRPCID, pktType, nil
			}
			// Still waiting for more fragments, but we've processed this one
			// Continue processing more packets
		case *packet.ErrorPacket:
			// Clean up stream context
			t.streamMutex.Lock()
			delete(t.streams, rpcID)
			t.streamMutex.Unlock()
			return []byte(p.ErrorMsg), addr, p.RPCID, pktType, nil
		default:
			logging.Debug("Unknown packet type", zap.Uint8("packetTypeID", uint8(packetTypeID)))
			return nil, nil, 0, packetTypeID, nil
		}
	}

	// If we get here, we processed packets but didn't get a complete message
	return nil, nil, 0, packetTypeID, nil
}

// ListenAndServe starts the HTTP/2 server (server only)
func (t *HTTP2Transport) ListenAndServe() error {
	if !t.isServer || t.server == nil {
		return fmt.Errorf("ListenAndServe can only be called on a server transport")
	}
	return t.server.ListenAndServe()
}

// ListenAndServeTLS starts the HTTP/2 server with TLS (server only)
func (t *HTTP2Transport) ListenAndServeTLS(certFile, keyFile string) error {
	if !t.isServer || t.server == nil {
		return fmt.Errorf("ListenAndServeTLS can only be called on a server transport")
	}
	return t.server.ListenAndServeTLS(certFile, keyFile)
}

// ReassembleDataPacket processes data packets through the reassembly layer
func (t *HTTP2Transport) ReassembleDataPacket(pkt *packet.DataPacket, addr *net.TCPAddr, packetTypeID packet.PacketTypeID) ([]byte, *net.TCPAddr, uint64, packet.PacketTypeID, error) {
	// Process fragment through reassembly layer
	fullMessage, _, reassembledRPCID, isComplete := t.reassembler.ProcessFragment(pkt, addr)

	if isComplete {
		// For responses, return the original source address from packet headers
		originalSrcAddr := &net.TCPAddr{
			IP:   net.IP(pkt.SrcIP[:]),
			Port: int(pkt.SrcPort),
		}
		return fullMessage, originalSrcAddr, reassembledRPCID, packetTypeID, nil
	}

	// Still waiting for more fragments
	return nil, nil, 0, packetTypeID, nil
}

func (t *HTTP2Transport) Close() error {
	t.streamMutex.Lock()
	defer t.streamMutex.Unlock()

	var err error
	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = t.server.Shutdown(ctx)
		t.server = nil
	}

	// Close streaming resources
	t.streamMu.Lock()
	if t.streamPipeW != nil {
		t.streamPipeW.Close()
		t.streamPipeW = nil
	}
	if t.streamPipeR != nil {
		t.streamPipeR.Close()
		t.streamPipeR = nil
	}
	t.streamConnected = false
	t.streamMu.Unlock()

	// Wait for streaming goroutine to finish
	t.streamReaderWg.Wait()

	if t.client != nil {
		// HTTP client doesn't need explicit closing in Go
		t.client = nil
	}

	// Close all streams
	for _, ctx := range t.streams {
		close(ctx.dataChan)
		close(ctx.errChan)
	}
	t.streams = make(map[uint64]*streamContext)

	// Clean up dispatcher: close all response channels and clear pending data
	if t.dispatcher != nil {
		t.dispatcher.responses.Range(func(key, value interface{}) bool {
			ch := value.(chan *responseData)
			close(ch)
			t.dispatcher.responses.Delete(key)
			return true
		})
		t.dispatcher.pendingData.Range(func(key, value interface{}) bool {
			t.dispatcher.pendingData.Delete(key)
			return true
		})
	}

	return err
}

// LocalAddr returns the local address of the transport
func (t *HTTP2Transport) LocalAddr() *net.TCPAddr {
	if t.server != nil && t.server.Addr != "" {
		addr, err := net.ResolveTCPAddr("tcp", t.server.Addr)
		if err == nil {
			return addr
		}
	}
	return nil
}

// GetResolver returns the resolver for this transport
func (t *HTTP2Transport) GetResolver() *balancer.Resolver {
	return t.resolver
}

// GetDispatcher returns the response dispatcher for advanced operations
func (t *HTTP2Transport) GetDispatcher() *ResponseDispatcher {
	return &ResponseDispatcher{d: t.dispatcher}
}
