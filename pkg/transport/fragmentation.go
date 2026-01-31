package transport

import (
	"net"
	"sync"

	protocol "github.com/appnet-org/arpc-h2/pkg/packet"
)

// DataReassembler handles the reassembly of fragmented data (request/response) packets
type DataReassembler struct {
	incoming map[uint64]map[uint16][]byte
	mu       sync.Mutex
}

// NewDataReassembler creates a new data reassembler
func NewDataReassembler() *DataReassembler {
	return &DataReassembler{
		incoming: make(map[uint64]map[uint16][]byte),
	}
}

// ProcessFragment processes a single data packet fragment and returns the reassembled message if complete
func (r *DataReassembler) ProcessFragment(pkt any, addr *net.TCPAddr) ([]byte, *net.TCPAddr, uint64, bool) {
	dataPkt := pkt.(*protocol.DataPacket)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Fast path: single-packet message (most common case for small payloads)
	if dataPkt.TotalPackets == 1 {
		return dataPkt.Payload, addr, dataPkt.RPCID, true
	}

	// Initialize fragment map for this RPC if it doesn't exist
	if _, exists := r.incoming[dataPkt.RPCID]; !exists {
		r.incoming[dataPkt.RPCID] = make(map[uint16][]byte, dataPkt.TotalPackets)
	}

	r.incoming[dataPkt.RPCID][dataPkt.SeqNumber] = dataPkt.Payload

	// Check if we have all fragments
	if len(r.incoming[dataPkt.RPCID]) == int(dataPkt.TotalPackets) {
		// Pre-calculate total size to avoid reallocations
		totalSize := 0
		for _, fragment := range r.incoming[dataPkt.RPCID] {
			totalSize += len(fragment)
		}

		// Reassemble the complete message by concatenating fragments in order
		fullMessage := make([]byte, 0, totalSize)
		for i := uint16(0); i < dataPkt.TotalPackets; i++ {
			fullMessage = append(fullMessage, r.incoming[dataPkt.RPCID][i]...)
		}

		// Clean up fragment storage and return complete message
		delete(r.incoming, dataPkt.RPCID)
		return fullMessage, addr, dataPkt.RPCID, true
	}

	// Still waiting for more fragments, return nil
	return nil, nil, 0, false
}

// FragmentData splits data into multiple packets for Data (Request/Response) packets
func (r *DataReassembler) FragmentData(data []byte, rpcID uint64, packetTypeID protocol.PacketTypeID, dstIP [4]byte, dstPort uint16, srcIP [4]byte, srcPort uint16) ([]any, error) {
	if packetTypeID == protocol.PacketTypeError || packetTypeID == protocol.PacketTypeUnknown {
		return []any{&protocol.ErrorPacket{
			RPCID:    rpcID,
			ErrorMsg: string(data),
		}}, nil
	}

	// Calculate chunk size by subtracting header overhead from max TCP payload
	// New header size: 1+8+2+2+4+2+4+2+4 = 29 bytes
	chunkSize := protocol.MaxTCPPayloadSize - 29
	totalPackets := uint16((len(data) + chunkSize - 1) / chunkSize)

	// Pre-allocate packets slice
	packets := make([]any, 0, totalPackets)

	for i := uint16(0); i < totalPackets; i++ {
		// Calculate start and end indices for current chunk
		start := int(i) * chunkSize
		end := min(start+chunkSize, len(data))

		// Create a packet for the current chunk
		pkt := &protocol.DataPacket{
			RPCID:        rpcID,
			TotalPackets: totalPackets,
			SeqNumber:    i,
			DstIP:        dstIP,
			DstPort:      dstPort,
			SrcIP:        srcIP,
			SrcPort:      srcPort,
			Payload:      data[start:end],
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}
