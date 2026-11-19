package openvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewFragmenterMinimumSize(t *testing.T) {
	if newFragmenter(0) != nil {
		t.Fatal("fragment size 0 must disable fragmentation")
	}
	if newFragmenter(fragMinSize-1) != nil {
		t.Fatal("fragment size below the OpenVPN minimum must be rejected")
	}
	if f := newFragmenter(fragMinSize); f == nil || f.size != fragMinSize {
		t.Fatalf("fragment size %d must be accepted, got %+v", fragMinSize, f)
	}
	if f := newFragmenter(1301); f == nil || f.size != 1300 {
		t.Fatalf("fragment size must be rounded down to a multiple of 4, got %+v", f)
	}
}

func TestFragmenterWholeFrame(t *testing.T) {
	f := newFragmenter(1300)
	payload := []byte("small datagram")
	fragments := f.split(payload)
	if len(fragments) != 1 {
		t.Fatalf("got %d fragments, want 1 whole frame", len(fragments))
	}
	if flags := binary.BigEndian.Uint32(fragments[0][:4]); flags != 0 {
		t.Fatalf("whole frame flags = %#x, want 0", flags)
	}
	got, complete := f.feed(fragments[0])
	if !complete {
		t.Fatal("whole frame must complete immediately")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("whole frame payload mismatch")
	}
}

func TestFragmenterRoundTrip(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 4000)
	fragments := f.split(payload)
	if len(fragments) != 4 {
		t.Fatalf("got %d fragments, want 4", len(fragments))
	}
	for i, fragment := range fragments {
		flags := binary.BigEndian.Uint32(fragment[:4])
		fragmentType := int(flags & fragTypeMask)
		wantType := fragTypePartial
		if i == len(fragments)-1 {
			wantType = fragTypeLast
		}
		if fragmentType != wantType {
			t.Fatalf("fragment %d type = %d, want %d", i, fragmentType, wantType)
		}
		if id := int((flags >> fragIDShift) & fragIDMask); id != i {
			t.Fatalf("fragment %d id = %d", i, id)
		}
		if seq := uint8((flags >> fragSeqShift) & fragSeqMask); seq != 0 {
			t.Fatalf("fragment %d sequence = %d, want 0", i, seq)
		}
		if wantType == fragTypeLast {
			size := int((flags>>fragSizeShift)&fragSizeMask) << fragSizeRoundShift
			if size != 1300 {
				t.Fatalf("last fragment size = %d, want 1300", size)
			}
		}
	}

	// Feed the fragments back in reverse order: reassembly must be order
	// independent and only complete on the last stored part.
	var reassembled []byte
	for i := len(fragments) - 1; i >= 0; i-- {
		got, complete := f.feed(fragments[i])
		if complete {
			if reassembled != nil {
				t.Fatal("completed twice")
			}
			reassembled = got
		}
	}
	if len(reassembled) != 0 && !bytes.Equal(reassembled, payload) {
		t.Fatal("reassembled payload mismatch")
	}
	if reassembled == nil {
		t.Fatal("reassembly never completed")
	}
}

func TestFragmenterIncomplete(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 4000)
	fragments := f.split(payload)
	for _, fragment := range fragments[:2] {
		if _, complete := f.feed(fragment); complete {
			t.Fatal("incomplete datagram must not complete")
		}
	}
	if f.inBytes != 2600 {
		t.Fatalf("buffered bytes = %d, want 2600", f.inBytes)
	}
	got, complete := f.feed(fragments[2])
	if complete {
		t.Fatal("datagram must still be incomplete")
	}
	got, complete = f.feed(fragments[3])
	if !complete || !bytes.Equal(got, payload) {
		t.Fatal("reassembly failed")
	}
	if f.inBytes != 0 || len(f.incoming) != 0 {
		t.Fatalf("buffers not released: bytes=%d buffers=%d", f.inBytes, len(f.incoming))
	}
}

func TestFragmenterDuplicateFragment(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 2000)
	fragments := f.split(payload)
	if _, complete := f.feed(fragments[0]); complete {
		t.Fatal("incomplete datagram must not complete")
	}
	if _, complete := f.feed(fragments[0]); complete {
		t.Fatal("duplicate fragment must not complete")
	}
	if f.inBytes != 1300 {
		t.Fatalf("duplicate fragment double counted: buffered bytes = %d", f.inBytes)
	}
	got, complete := f.feed(fragments[1])
	if !complete || !bytes.Equal(got, payload) {
		t.Fatal("reassembly after duplicate failed")
	}
}

func TestFragmenterPingPacket(t *testing.T) {
	f := newFragmenter(1300)
	fragments := f.split(openVPNPingPacket)
	if len(fragments) != 1 {
		t.Fatalf("ping must travel as one whole frame, got %d fragments", len(fragments))
	}
	if len(fragments[0]) != 4+len(openVPNPingPacket) {
		t.Fatalf("framed ping length = %d", len(fragments[0]))
	}
	got, complete := f.feed(fragments[0])
	if !complete {
		t.Fatal("framed ping must complete immediately")
	}
	if !IsPingPacket(got) {
		t.Fatal("framed ping did not survive the frame")
	}
}

func TestFragmenterSpuriousWholeFlags(t *testing.T) {
	f := newFragmenter(1300)
	frame := prependFragmentHeader([]byte("payload"), fragTypeWhole, 7, 3, 0)
	if _, complete := f.feed(frame); complete {
		t.Fatal("whole frame with a sequence or fragment id must be rejected")
	}
}

func TestFragmenterUnknownType(t *testing.T) {
	f := newFragmenter(1300)
	frame := make([]byte, 8)
	binary.BigEndian.PutUint32(frame[:4], 3) // fragment type 3 is not defined
	if _, complete := f.feed(frame); complete {
		t.Fatal("unknown fragment type must be rejected")
	}
	if _, complete := f.feed([]byte{0x00}); complete {
		t.Fatal("short payload must be rejected")
	}
}

func TestFragmenterSequenceIDIncrements(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 2000)

	first := f.split(payload)
	second := f.split(payload)
	whole := f.split([]byte("tiny"))
	if seq := uint8((binary.BigEndian.Uint32(first[0][:4]) >> fragSeqShift) & fragSeqMask); seq != 0 {
		t.Fatalf("first datagram sequence = %d, want 0", seq)
	}
	if seq := uint8((binary.BigEndian.Uint32(second[0][:4]) >> fragSeqShift) & fragSeqMask); seq != 1 {
		t.Fatalf("second datagram sequence = %d, want 1", seq)
	}
	if flags := binary.BigEndian.Uint32(whole[0][:4]); flags != 0 {
		t.Fatalf("whole frames must not consume a sequence id, flags = %#x", flags)
	}
}

func TestFragmenterSequenceIDWraps(t *testing.T) {
	f := newFragmenter(1300)
	f.outSeq = 0xff
	payload := bytes.Repeat([]byte{0x45}, 2000)
	fragments := f.split(payload)
	if seq := uint8((binary.BigEndian.Uint32(fragments[0][:4]) >> fragSeqShift) & fragSeqMask); seq != 0xff {
		t.Fatalf("sequence = %d, want 255", seq)
	}
	if f.outSeq != 0 {
		t.Fatalf("sequence did not wrap: %d", f.outSeq)
	}
	// The wrapped sequence must still reassemble.
	var got []byte
	for _, fragment := range fragments {
		if out, complete := f.feed(fragment); complete {
			got = out
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembly across the sequence wrap failed")
	}
}

func TestFragmenterTooManyParts(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 1300*fragMaxParts+1)
	if fragments := f.split(payload); fragments != nil {
		t.Fatalf("payload needing %d parts must be dropped", fragMaxParts+1)
	}
}

func TestFragmenterExpire(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 2000)
	fragments := f.split(payload)
	if _, complete := f.feed(fragments[0]); complete {
		t.Fatal("incomplete datagram must not complete")
	}
	f.mu.Lock()
	for _, buffer := range f.incoming {
		buffer.updated = time.Now().Add(-fragReassemblyTimeout - time.Second)
	}
	f.mu.Unlock()
	if _, complete := f.feed(fragments[1]); complete {
		t.Fatal("stale buffer must be expired, not completed")
	}
	if f.inBytes != 700 {
		t.Fatalf("buffered bytes = %d, want only the new fragment", f.inBytes)
	}
}

func TestFragmenterReceiveWindow(t *testing.T) {
	f := newFragmenter(1300)
	payload := bytes.Repeat([]byte{0x45}, 2000)
	fragments := f.split(payload) // sequence 0
	if _, complete := f.feed(fragments[0]); complete {
		t.Fatal("incomplete datagram must not complete")
	}
	// A datagram far ahead in the sequence space discards the stale buffer.
	f.outSeq = 200
	next := f.split(payload)
	if out, complete := f.feed(next[0]); complete || out != nil {
		t.Fatal("new datagram must not complete on its first fragment")
	}
	if _, ok := f.incoming[0]; ok {
		t.Fatal("out of window buffer was not dropped")
	}
}

func TestFragmenterSequenceDifference(t *testing.T) {
	tests := []struct {
		sequence  uint8
		reference uint8
		want      int
	}{
		{5, 5, 0},
		{6, 5, 1},
		{4, 5, -1},
		{0, 255, 1},
		{255, 0, -1},
		{200, 0, -56},
		{0, 200, 56},
	}
	for _, test := range tests {
		if got := fragSequenceDifference(test.sequence, test.reference); got != test.want {
			t.Fatalf("fragSequenceDifference(%d, %d) = %d, want %d", test.sequence, test.reference, got, test.want)
		}
	}
}

func TestInstallScriptOptionsStringFragment(t *testing.T) {
	withoutFragment := InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA512, "", 0)
	if withoutFragment != "V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth SHA512,keysize 256,key-method 2,tls-client" {
		t.Fatalf("unexpected options string without fragment: %s", withoutFragment)
	}

	withFragment := InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA512, "", 1300)
	if !strings.Contains(withFragment, "link-mtu 1554") {
		t.Fatalf("fragment header must be added to link-mtu: %s", withFragment)
	}
	if !strings.Contains(withFragment, "mtu-dynamic,") {
		t.Fatalf("fragment must be advertised with mtu-dynamic: %s", withFragment)
	}

	withBoth := InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA512, CompLzoYes, 1300)
	if !strings.Contains(withBoth, "link-mtu 1548") {
		t.Fatalf("comp-lzo link-mtu must also grow by 4: %s", withBoth)
	}
	if !strings.Contains(withBoth, "comp-lzo,mtu-dynamic,") {
		t.Fatalf("comp-lzo must be followed by mtu-dynamic: %s", withBoth)
	}
}

// countingPacketIO records how many datagrams a client actually put on the
// wire, so fragmentation can be asserted from the transport side.
type countingPacketIO struct {
	PacketIO
	written atomic.Int64
}

func (c *countingPacketIO) WritePacket(packet []byte) error {
	c.written.Add(1)
	return c.PacketIO.WritePacket(packet)
}

func TestFragmentingDataChannelRoundTrip(t *testing.T) {
	clientIO, peerIO := newMemoryPacketPair()
	clientCtx, cancelClient := context.WithCancel(context.Background())
	peerCtx, cancelPeer := context.WithCancel(context.Background())
	defer cancelClient()
	defer cancelPeer()

	wire := &countingPacketIO{PacketIO: &controlIOPacketAdapter{io: clientIO, ctx: clientCtx, cancel: cancelClient}}
	client, err := NewClient(&ClientConfig{Fragment: 1300}, wire)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := NewClient(&ClientConfig{Fragment: 1300}, &controlIOPacketAdapter{io: peerIO, ctx: peerCtx, cancel: cancelPeer})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	peerKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x33}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x11}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
	}
	clientData, err := NewDataChannel(clientKeys, CipherAES128GCM, AuthSHA256, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	peerData, err := NewDataChannel(peerKeys, CipherAES128GCM, AuthSHA256, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(clientData)
	peer.installDataChannel(peerData)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A packet that fits travels as one whole frame.
	small := bytes.Repeat([]byte{0x45}, 1200)
	if err := client.WriteIPPacket(ctx, small); err != nil {
		t.Fatal(err)
	}
	got, err := peer.ReadIPPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, small) {
		t.Fatal("whole frame payload mismatch")
	}
	if n := wire.written.Load(); n != 1 {
		t.Fatalf("whole frame wrote %d datagrams, want 1", n)
	}

	// A packet above the fragment size is split, each piece encrypted with its
	// own packet id, and reassembled on the peer.
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := client.WriteIPPacket(ctx, payload); err != nil {
		t.Fatal(err)
	}
	got, err = peer.ReadIPPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled payload mismatch")
	}
	if n := wire.written.Load(); n != 4 {
		t.Fatalf("split datagram wrote %d datagrams in total, want 4", n)
	}

	// Keepalive pings are framed too, otherwise the peer would trip over them.
	if err := client.WritePing(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for wire.written.Load() != 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := wire.written.Load(); n != 5 {
		t.Fatalf("ping wrote %d datagrams in total, want 5", n)
	}
}
