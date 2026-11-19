package openvpn

import (
	"encoding/binary"
	"sync"
	"time"
)

// OpenVPN data channel fragmentation (--fragment).
//
// The 4 byte fragment header is part of the plaintext payload, so it is
// encrypted and authenticated together with the IP packet. The framing order
// therefore is:
//
//	send:    [compress] -> [fragment header] -> encrypt
//	receive: decrypt -> [reassembly] -> [decompress]
//
// Header layout, one big endian uint32 (see OpenVPN fragment.h):
//
//	bit  0..1   type     0 = whole, 1 = partial, 2 = last
//	bit  2..9   seq id   8 bits, shared by all fragments of one datagram
//	bit 10..14  frag id  5 bits, 0..31
//	bit 15..29  size     15 bits, only set on the last fragment, size >> 2
const (
	fragTypeWhole   = 0
	fragTypePartial = 1
	fragTypeLast    = 2

	fragTypeMask  = 0x00000003
	fragTypeShift = 0

	fragSeqMask  = 0x000000ff
	fragSeqShift = 2

	fragIDMask  = 0x0000001f
	fragIDShift = 10

	fragSizeMask  = 0x00003fff
	fragSizeShift = 15

	// fragSizeRoundShift is the power of two OpenVPN rounds fragment sizes
	// with (FRAG_SIZE_ROUND_SHIFT).
	fragSizeRoundShift = 2

	// fragMaxParts mirrors OpenVPN MAX_FRAGS.
	fragMaxParts = 32

	// fragMinSize mirrors the lower bound OpenVPN enforces on --fragment.
	fragMinSize = 68

	// mssFixMin is the smallest useful --mssfix value: one IPv4+TCP header plus
	// a minimal segment.
	mssFixMin = 64

	// fragReceiveWindow bounds how far out of order a sequence id may be
	// before older reassembly buffers are abandoned.
	fragReceiveWindow = 25

	fragReassemblyTimeout  = 30 * time.Second
	fragMaxPacketBytes     = 1<<16 - 1
	fragMaxReassemblyBytes = 4 << 20
)

// fragBuffer collects the fragments of one datagram, keyed by sequence id.
type fragBuffer struct {
	maxSize int
	lastID  int
	parts   map[int][]byte
	bytes   int
	updated time.Time
}

// fragmenter implements OpenVPN data channel fragmentation and reassembly.
// A nil *fragmenter is valid and means fragmentation is disabled.
type fragmenter struct {
	size int

	mu       sync.Mutex
	outSeq   uint8
	incoming map[uint8]*fragBuffer
	inBytes  int
	inSeq    uint8
	inSeqSet bool
}

// newFragmenter returns a fragmenter for size byte payloads, or nil when the
// size is unusable. The size is rounded down to a four byte boundary the same
// way OpenVPN does.
func newFragmenter(size int) *fragmenter {
	size &^= (1 << fragSizeRoundShift) - 1
	if size < fragMinSize {
		return nil
	}
	return &fragmenter{
		size:     size,
		incoming: make(map[uint8]*fragBuffer),
	}
}

// prependFragmentHeader frames payload with the 4 byte fragment header.
func prependFragmentHeader(payload []byte, fragmentType int, sequenceID uint8, fragmentID, maxFragmentSize int) []byte {
	flags := uint32(fragmentType&fragTypeMask) << fragTypeShift
	flags |= uint32(sequenceID&fragSeqMask) << fragSeqShift
	flags |= uint32(fragmentID&fragIDMask) << fragIDShift
	if fragmentType == fragTypeLast {
		flags |= uint32(maxFragmentSize&fragSizeMask) << fragSizeShift
	}
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[:4], flags)
	copy(framed[4:], payload)
	return framed
}

// split frames payload for the wire. Once fragment is negotiated every data
// packet carries a header, so small payloads become a single whole frame.
// A nil result means the payload cannot be represented and must be dropped.
func (f *fragmenter) split(payload []byte) [][]byte {
	if len(payload) <= f.size {
		return [][]byte{prependFragmentHeader(payload, fragTypeWhole, 0, 0, 0)}
	}

	f.mu.Lock()
	seq := f.outSeq
	f.outSeq++
	f.mu.Unlock()

	fragments := make([][]byte, 0, len(payload)/f.size+1)
	for offset, fragmentID := 0, 0; offset < len(payload); fragmentID++ {
		if fragmentID >= fragMaxParts {
			return nil
		}
		chunkSize := f.size
		if rest := len(payload) - offset; rest < chunkSize {
			chunkSize = rest
		}
		fragmentType := fragTypePartial
		maxFragmentSize := 0
		if offset+chunkSize >= len(payload) {
			fragmentType = fragTypeLast
			maxFragmentSize = f.size >> fragSizeRoundShift
		}
		fragments = append(fragments, prependFragmentHeader(
			payload[offset:offset+chunkSize], fragmentType, seq, fragmentID, maxFragmentSize))
		offset += chunkSize
	}
	return fragments
}

// feed consumes one decrypted data packet and reports whether it completes a
// datagram, in which case the reassembled payload is returned.
func (f *fragmenter) feed(payload []byte) ([]byte, bool) {
	if len(payload) < 4 {
		return nil, false
	}
	flags := binary.BigEndian.Uint32(payload[:4])
	fragmentType := int((flags >> fragTypeShift) & fragTypeMask)
	fragmentPayload := payload[4:]

	switch fragmentType {
	case fragTypeWhole:
		if (flags>>fragSeqShift)&fragSeqMask != 0 || (flags>>fragIDShift)&fragIDMask != 0 {
			return nil, false
		}
		return fragmentPayload, true
	case fragTypePartial, fragTypeLast:
		return f.store(
			uint8((flags>>fragSeqShift)&fragSeqMask),
			int((flags>>fragIDShift)&fragIDMask),
			int((flags>>fragSizeShift)&fragSizeMask)<<fragSizeRoundShift,
			fragmentType == fragTypeLast,
			fragmentPayload,
		)
	default:
		return nil, false
	}
}

func (f *fragmenter) store(sequenceID uint8, fragmentID, maxFragmentSize int, last bool, payload []byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	f.expire(now)

	if len(payload) > fragMaxPacketBytes {
		f.drop(sequenceID)
		return nil, false
	}
	f.advanceWindow(sequenceID)

	buffer, exists := f.incoming[sequenceID]
	fragmentSize := len(payload)
	if maxFragmentSize > 0 {
		fragmentSize = maxFragmentSize
	}
	if exists && buffer.maxSize != fragmentSize {
		f.drop(sequenceID)
		buffer, exists = nil, false
	}
	if !exists {
		buffer = &fragBuffer{
			maxSize: fragmentSize,
			lastID:  -1,
			parts:   make(map[int][]byte),
			updated: now,
		}
		f.incoming[sequenceID] = buffer
	}

	previous := buffer.parts[fragmentID]
	additionalBytes := len(payload) - len(previous)
	if buffer.bytes+additionalBytes > fragMaxPacketBytes {
		f.drop(sequenceID)
		return nil, false
	}
	for f.inBytes+additionalBytes > fragMaxReassemblyBytes {
		oldest, found := f.oldest(sequenceID)
		if !found {
			f.drop(sequenceID)
			return nil, false
		}
		f.drop(oldest)
	}
	buffer.parts[fragmentID] = append([]byte{}, payload...)
	buffer.bytes += additionalBytes
	buffer.updated = now
	f.inBytes += additionalBytes
	if last {
		buffer.lastID = fragmentID
	}
	if buffer.lastID < 0 {
		return nil, false
	}

	total := 0
	for id := 0; id <= buffer.lastID; id++ {
		part, ok := buffer.parts[id]
		if !ok {
			return nil, false
		}
		total += len(part)
	}
	reassembled := make([]byte, 0, total)
	for id := 0; id <= buffer.lastID; id++ {
		reassembled = append(reassembled, buffer.parts[id]...)
	}
	f.drop(sequenceID)
	return reassembled, true
}

// advanceWindow discards buffers that fell out of the receive window or were
// already superseded, so a lossy high rate link cannot pin memory forever.
func (f *fragmenter) advanceWindow(sequenceID uint8) {
	if !f.inSeqSet {
		f.inSeq = sequenceID
		f.inSeqSet = true
		return
	}
	difference := fragSequenceDifference(sequenceID, f.inSeq)
	if difference >= fragReceiveWindow || difference <= -fragReceiveWindow {
		f.clear()
		f.inSeq = sequenceID
		return
	}
	if difference <= 0 {
		return
	}
	f.inSeq = sequenceID
	for bufferedSeq := range f.incoming {
		bufferedDifference := fragSequenceDifference(bufferedSeq, f.inSeq)
		if bufferedDifference <= -fragReceiveWindow || bufferedDifference > 0 {
			f.drop(bufferedSeq)
		}
	}
}

// fragSequenceDifference returns signed distance between sequence ids, taking
// the 8 bit wrap around into account.
func fragSequenceDifference(sequenceID, referenceSequence uint8) int {
	direct := int(sequenceID) - int(referenceSequence)
	if direct == 0 {
		return 0
	}
	wrapped := direct
	if sequenceID > referenceSequence {
		wrapped -= fragSeqMask + 1
	} else {
		wrapped += fragSeqMask + 1
	}
	if direct < 0 {
		if -direct <= wrapped {
			return direct
		}
		return wrapped
	}
	if direct <= -wrapped {
		return direct
	}
	return wrapped
}

func (f *fragmenter) expire(now time.Time) {
	for sequenceID, buffer := range f.incoming {
		if buffer.updated.IsZero() || now.Sub(buffer.updated) >= fragReassemblyTimeout {
			f.drop(sequenceID)
		}
	}
}

func (f *fragmenter) oldest(excludeSequenceID uint8) (uint8, bool) {
	oldestSequenceID := uint8(0)
	var oldestTime time.Time
	found := false
	for sequenceID, buffer := range f.incoming {
		if sequenceID == excludeSequenceID {
			continue
		}
		if !found || buffer.updated.Before(oldestTime) {
			oldestSequenceID = sequenceID
			oldestTime = buffer.updated
			found = true
		}
	}
	return oldestSequenceID, found
}

func (f *fragmenter) clear() {
	for sequenceID := range f.incoming {
		f.drop(sequenceID)
	}
}

func (f *fragmenter) drop(sequenceID uint8) {
	buffer, ok := f.incoming[sequenceID]
	if !ok {
		return
	}
	delete(f.incoming, sequenceID)
	f.inBytes -= buffer.bytes
	if f.inBytes < 0 {
		f.inBytes = 0
	}
}
