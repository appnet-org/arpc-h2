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
)

// GenerateRPCID creates a unique RPC ID
func GenerateRPCID() uint64 {
	return uint64(time.Now().UnixNano())
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
	}

	// Configure HTTP/2 server (handler will be set by SetHandler)
	server := &http.Server{
		Addr: address,
	}

	// Enable HTTP/2
	http2.ConfigureServer(server, &http2.Server{})

	transport.server = server

	return transport, nil
}

// NewHTTP2ClientTransport creates an HTTP/2 transport for client use
func NewHTTP2ClientTransport() (*HTTP2Transport, error) {
	// Configure HTTP/2 client
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
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
	}
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
			packetLen := uint32(len(packetData))
			lenBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBuf, packetLen)
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

		// Store response in stream context
		t.streamMutex.Lock()
		ctx := &streamContext{
			dataChan:   make(chan []byte, 1),
			addr:       nil, // Client doesn't need addr
			rpcID:      rpcID,
			packetType: packetTypeID,
			errChan:    make(chan error, 1),
		}
		ctx.dataChan <- respBody
		t.streams[rpcID] = ctx
		t.streamMutex.Unlock()

		return nil
	}
}

// Receive takes a buffer size as input, reads data from the HTTP/2 stream, and returns
// the following information when receiving the complete data for an RPC message:
// * complete data for a message (if no message is complete, it will return nil)
// * original source address from connection (for responses)
// * RPC id
// * packet type
// * error
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

// SetHandler sets a custom handler for the server (server only)
func (t *HTTP2Transport) SetHandler(handler http.HandlerFunc) {
	if t.isServer {
		t.handler = handler
		t.server.Handler = handler
	}
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
