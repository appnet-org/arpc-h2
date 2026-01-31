package transport

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/appnet-org/arpc-h2/pkg/packet"
)

// flusher interface for http.ResponseWriter.Flush()
type flusher interface {
	Flush()
}

// StreamWriter provides thread-safe writing to an io.Writer with flushing support
type StreamWriter struct {
	w      io.Writer
	flush  flusher
	mu     sync.Mutex
	closed bool
}

// NewStreamWriter creates a new StreamWriter
func NewStreamWriter(w io.Writer) *StreamWriter {
	sw := &StreamWriter{w: w}
	if f, ok := w.(flusher); ok {
		sw.flush = f
	}
	return sw
}

// WriteFrame writes a length-prefixed packet frame to the writer (thread-safe)
func (sw *StreamWriter) WriteFrame(packetData []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return fmt.Errorf("stream writer is closed")
	}

	return writeFrame(sw.w, packetData)
}

// WriteFrameAndFlush writes a frame and flushes (thread-safe)
func (sw *StreamWriter) WriteFrameAndFlush(packetData []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return fmt.Errorf("stream writer is closed")
	}

	if err := writeFrame(sw.w, packetData); err != nil {
		return err
	}

	if sw.flush != nil {
		sw.flush.Flush()
	}
	return nil
}

// Close marks the writer as closed
func (sw *StreamWriter) Close() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.closed = true
}

// Reusable length buffer to reduce allocations
var lenBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4)
	},
}

// writeFrame writes a length-prefixed packet frame: [len(4B)][packetData]
func writeFrame(w io.Writer, packetData []byte) error {
	lenBuf := lenBufPool.Get().([]byte)
	defer lenBufPool.Put(lenBuf)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(packetData)))

	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write frame length: %w", err)
	}
	if _, err := w.Write(packetData); err != nil {
		return fmt.Errorf("failed to write frame data: %w", err)
	}
	return nil
}

// readFrame reads a length-prefixed packet frame from a buffered reader
// Returns the packet bytes (without length prefix)
func readFrame(r *bufio.Reader) ([]byte, error) {
	// Read 4-byte length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}

	packetLen := binary.LittleEndian.Uint32(lenBuf)
	if packetLen > uint32(packet.MaxTCPPayloadSize) {
		return nil, fmt.Errorf("packet length %d exceeds max size %d", packetLen, packet.MaxTCPPayloadSize)
	}

	// Read packet data
	packetData := make([]byte, packetLen)
	if _, err := io.ReadFull(r, packetData); err != nil {
		return nil, err
	}

	return packetData, nil
}

// ProcessPacketResult represents the result of processing a single packet
type ProcessPacketResult struct {
	Data       []byte
	Addr       *net.TCPAddr
	RPCID      uint64
	PacketType packet.PacketTypeID
	IsComplete bool
	IsError    bool
}

// ProcessSinglePacket processes a single packet's bytes through deserialization and reassembly
// This is the incremental version of ProcessReceivedData for streaming mode
func (t *HTTP2Transport) ProcessSinglePacket(packetData []byte, addr *net.TCPAddr) (*ProcessPacketResult, error) {
	// Deserialize packet
	pkt, pktType, err := packet.DeserializePacket(packetData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize packet: %w", err)
	}

	result := &ProcessPacketResult{
		PacketType: pktType,
	}

	// Handle different packet types
	switch p := pkt.(type) {
	case *packet.DataPacket:
		// Process fragment through reassembly layer
		message, _, reassembledRPCID, isComplete := t.reassembler.ProcessFragment(p, addr)
		if isComplete {
			result.Data = message
			result.Addr = addr
			result.RPCID = reassembledRPCID
			result.IsComplete = true
		} else {
			// Still waiting for more fragments
			result.RPCID = p.RPCID
			result.IsComplete = false
		}
	case *packet.ErrorPacket:
		result.Data = []byte(p.ErrorMsg)
		result.RPCID = p.RPCID
		result.IsComplete = true
		result.IsError = true
	default:
		return nil, fmt.Errorf("unknown packet type")
	}

	return result, nil
}

// SerializeAndWriteFrame serializes a packet and writes it as a frame
func SerializeAndWriteFrame(w io.Writer, pkt any) error {
	var packetData []byte
	var err error

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

	return writeFrame(w, packetData)
}

// FragmentAndWriteFrames fragments data and writes all frames
func FragmentAndWriteFrames(w io.Writer, reassembler *DataReassembler, data []byte, rpcID uint64, packetTypeID packet.PacketTypeID) error {
	var dstIP, srcIP [4]byte
	var dstPort, srcPort uint16

	packets, err := reassembler.FragmentData(data, rpcID, packetTypeID, dstIP, dstPort, srcIP, srcPort)
	if err != nil {
		return fmt.Errorf("failed to fragment data: %w", err)
	}

	for _, pkt := range packets {
		if err := SerializeAndWriteFrame(w, pkt); err != nil {
			return err
		}
	}

	return nil
}

// StreamReader wraps a bufio.Reader for reading frames
type StreamReader struct {
	r *bufio.Reader
}

// NewStreamReader creates a new StreamReader from an io.Reader
func NewStreamReader(r io.Reader) *StreamReader {
	if br, ok := r.(*bufio.Reader); ok {
		return &StreamReader{r: br}
	}
	return &StreamReader{r: bufio.NewReaderSize(r, 64*1024)} // 64KB buffer
}

// ReadFrame reads the next frame from the stream
func (sr *StreamReader) ReadFrame() ([]byte, error) {
	return readFrame(sr.r)
}

// ReadAndProcessPacket reads a frame and processes it through deserialization/reassembly
func (sr *StreamReader) ReadAndProcessPacket(transport *HTTP2Transport, addr *net.TCPAddr) (*ProcessPacketResult, error) {
	packetData, err := sr.ReadFrame()
	if err != nil {
		return nil, err
	}
	return transport.ProcessSinglePacket(packetData, addr)
}
