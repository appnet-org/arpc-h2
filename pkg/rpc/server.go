package rpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/appnet-org/arpc-h2/pkg/logging"
	"github.com/appnet-org/arpc-h2/pkg/packet"
	"github.com/appnet-org/arpc-h2/pkg/serializer"
	"github.com/appnet-org/arpc-h2/pkg/transport"
	"go.uber.org/zap"
)

// MethodHandler defines the function signature for handling an RPC method.
type MethodHandler func(srv any, ctx context.Context, dec func(any) error) (resp any, err error)

// MethodDesc represents an RPC service's method specification.
type MethodDesc struct {
	MethodName string
	Handler    MethodHandler
}

// ServiceDesc describes an RPC service, including its implementation and methods.
type ServiceDesc struct {
	ServiceImpl any
	ServiceName string
	Methods     map[string]*MethodDesc
}

// Server is the core RPC server handling transport, serialization, and registered services.
type Server struct {
	transport  *transport.HTTP2Transport
	serializer serializer.Serializer
	services   map[string]*ServiceDesc
}

// NewServer initializes a new Server instance with the given address and serializer.
func NewServer(addr string, serializer serializer.Serializer) (*Server, error) {
	http2Transport, err := transport.NewHTTP2Transport(addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		transport:  http2Transport,
		serializer: serializer,
		services:   make(map[string]*ServiceDesc),
	}, nil
}

// RegisterService registers a service and its methods with the server.
func (s *Server) RegisterService(desc *ServiceDesc, impl any) {
	s.services[desc.ServiceName] = desc
	logging.Info("Registered service", zap.String("serviceName", desc.ServiceName))
}

// parseFramedRequest extracts service, method, and payload segments from a request frame.
// Wire format: [serviceLen(2B)][service][methodLen(2B)][method][payload]
func (s *Server) parseFramedRequest(data []byte) (string, string, []byte, error) {
	offset := 0

	// Service
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("data too short for service length")
	}
	serviceLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+serviceLen > len(data) {
		return "", "", nil, fmt.Errorf("service length %d exceeds data length", serviceLen)
	}
	service := string(data[offset : offset+serviceLen])
	offset += serviceLen

	// Method
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("data too short for method length")
	}
	methodLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+methodLen > len(data) {
		return "", "", nil, fmt.Errorf("method length %d exceeds data length", methodLen)
	}
	method := string(data[offset : offset+methodLen])
	offset += methodLen

	// Payload
	payload := data[offset:]

	return service, method, payload, nil
}

// frameResponse constructs a binary message with
// [serviceLen(2B)][service][methodLen(2B)][method][payload]
func (s *Server) frameResponse(service, method string, payload []byte) ([]byte, error) {
	// total size = 2 + len(service) + 2 + len(method) + len(payload)
	totalSize := 4 + len(service) + len(method) + len(payload)
	buf := make([]byte, totalSize)

	// service length
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(service)))
	copy(buf[2:], service)

	// method length
	methodStart := 2 + len(service)
	binary.LittleEndian.PutUint16(buf[methodStart:methodStart+2], uint16(len(method)))
	copy(buf[methodStart+2:], method)

	// payload
	payloadStart := methodStart + 2 + len(method)
	copy(buf[payloadStart:], payload)

	return buf, nil
}

// Start begins listening for incoming RPC requests, dispatching to the appropriate service/method handler.
func (s *Server) Start() {
	logging.Info("Server started... Waiting for HTTP/2 connections.")

	s.transport.SetHandler(s.handleHTTP2Request)

	// Start HTTP/2 server
	if err := s.transport.ListenAndServe(); err != nil {
		logging.Error("Error starting HTTP/2 server", zap.Error(err))
	}
}

// handleHTTP2Request handles HTTP/2 requests
func (s *Server) handleHTTP2Request(w http.ResponseWriter, r *http.Request) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Extract remote address
	remoteAddr := r.RemoteAddr
	tcpAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		http.Error(w, "Failed to resolve remote address", http.StatusBadRequest)
		return
	}

	// Create a transport instance for this request to process packets
	connTransport := transport.NewHTTP2TransportForStream(s.transport.GetResolver())

	// Process the request body as packets to extract the RPC data
	data, _, rpcID, _, err := connTransport.ProcessReceivedData(body, tcpAddr, 0, packet.PacketTypeData, packet.MaxTCPPayloadSize)
	if err != nil {
		logging.Error("Error processing request", zap.Error(err))
		http.Error(w, "Failed to process request", http.StatusBadRequest)
		return
	}

	if data == nil {
		http.Error(w, "No data received", http.StatusBadRequest)
		return
	}

	// Parse request payload
	serviceName, methodName, reqPayloadBytes, err := s.parseFramedRequest(data)
	if err != nil {
		logging.Error("Failed to parse framed request", zap.Error(err))
		// Send error response
		s.sendErrorResponse(w, rpcID, []byte(err.Error()), packet.PacketTypeUnknown)
		return
	}

	// Create context
	ctx := context.Background()

	// Lookup service and method
	svcDesc, ok := s.services[serviceName]
	if !ok {
		logging.Warn("Unknown service", zap.String("serviceName", serviceName))
		s.sendErrorResponse(w, rpcID, []byte("unknown service"), packet.PacketTypeError)
		return
	}
	methodDesc, ok := svcDesc.Methods[methodName]
	if !ok {
		logging.Warn("Unknown method",
			zap.String("serviceName", serviceName),
			zap.String("methodName", methodName))
		s.sendErrorResponse(w, rpcID, []byte("unknown method"), packet.PacketTypeError)
		return
	}

	// Invoke method handler
	resp, err := methodDesc.Handler(svcDesc.ServiceImpl, ctx, func(v any) error {
		return s.serializer.Unmarshal(reqPayloadBytes, v)
	})
	if err != nil {
		var errType packet.PacketTypeID
		if rpcErr, ok := err.(*RPCError); ok && rpcErr.Type == RPCFailError {
			errType = packet.PacketTypeError
		} else {
			errType = packet.PacketTypeUnknown
			logging.Error("Handler error", zap.Error(err))
		}
		s.sendErrorResponse(w, rpcID, []byte(err.Error()), errType)
		return
	}

	// Serialize response
	respPayloadBytes, err := s.serializer.Marshal(resp)
	if err != nil {
		logging.Error("Error marshaling response", zap.Error(err))
		s.sendErrorResponse(w, rpcID, []byte(err.Error()), packet.PacketTypeUnknown)
		return
	}

	// Frame response
	framedResp, err := s.frameResponse(serviceName, methodName, respPayloadBytes)
	if err != nil {
		logging.Error("Failed to frame response", zap.Error(err))
		s.sendErrorResponse(w, rpcID, []byte(err.Error()), packet.PacketTypeUnknown)
		return
	}

	// Send the response via HTTP/2
	s.sendResponse(w, rpcID, framedResp, packet.PacketTypeData)
}

// sendResponse sends a response through HTTP/2
func (s *Server) sendResponse(w http.ResponseWriter, rpcID uint64, data []byte, packetTypeID packet.PacketTypeID) {
	// Use the transport to format the response data as packets
	// Extract destination info (not used in HTTP/2 but needed for packet format)
	var dstIP [4]byte
	var dstPort uint16
	var srcIP [4]byte
	var srcPort uint16

	// Create a reassembler for fragmenting the response
	reassembler := transport.NewDataReassembler()

	// Fragment the data into packets
	packets, err := reassembler.FragmentData(data, rpcID, packetTypeID, dstIP, dstPort, srcIP, srcPort)
	if err != nil {
		logging.Error("Error fragmenting response", zap.Error(err))
		http.Error(w, "Error fragmenting response", http.StatusInternalServerError)
		return
	}

	// Serialize all packets into response body
	var responseData bytes.Buffer
	for _, pkt := range packets {
		var packetData []byte
		switch p := pkt.(type) {
		case *packet.DataPacket:
			packetData, err = packet.SerializeDataPacket(p)
		case *packet.ErrorPacket:
			packetData, err = packet.SerializeErrorPacket(p)
		default:
			http.Error(w, "Unknown packet type", http.StatusInternalServerError)
			return
		}

		if err != nil {
			logging.Error("Error serializing packet", zap.Error(err))
			http.Error(w, "Error serializing packet", http.StatusInternalServerError)
			return
		}

		// Write packet length first (4 bytes) for framing
		packetLen := uint32(len(packetData))
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, packetLen)
		responseData.Write(lenBuf)
		responseData.Write(packetData)
	}

	// Send response
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(responseData.Bytes())
}

// sendErrorResponse sends an error response through HTTP/2
func (s *Server) sendErrorResponse(w http.ResponseWriter, rpcID uint64, errMsg []byte, errType packet.PacketTypeID) {
	s.sendResponse(w, rpcID, errMsg, errType)
}

// GetTransport returns the underlying transport for advanced operations
func (s *Server) GetTransport() *transport.HTTP2Transport {
	return s.transport
}
