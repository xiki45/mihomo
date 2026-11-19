package openvpn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// newFramedPair wires two clients over an in-memory transport with mirrored
// data channel keys so payloads can be pushed through the full encrypt,
// frame and reassemble path.
func newFramedPair(t *testing.T, clientConfig, peerConfig *ClientConfig) (*Client, *Client, *countingPacketIO) {
	t.Helper()
	clientIO, peerIO := newMemoryPacketPair()
	clientCtx, cancelClient := context.WithCancel(context.Background())
	peerCtx, cancelPeer := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancelClient()
		cancelPeer()
	})

	wire := &countingPacketIO{PacketIO: &controlIOPacketAdapter{io: clientIO, ctx: clientCtx, cancel: cancelClient}}
	client, err := NewClient(clientConfig, wire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	peer, err := NewClient(peerConfig, &controlIOPacketAdapter{io: peerIO, ctx: peerCtx, cancel: cancelPeer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })

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
	return client, peer, wire
}

// comp-lzo no still frames the data channel with the no-compress byte, so a
// payload must survive the stub head on both ends.
func TestCompLzoNoStubRoundTrip(t *testing.T) {
	client, peer, wire := newFramedPair(t, &ClientConfig{CompLZO: CompLzoNo, Fragment: 1300}, &ClientConfig{CompLZO: CompLzoNo, Fragment: 1300})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte{0x45}, 3000)
	if err := client.WriteIPPacket(ctx, payload); err != nil {
		t.Fatal(err)
	}
	got, err := peer.ReadIPPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch through the comp-lzo stub")
	}
	if n := wire.written.Load(); n != 3 {
		t.Fatalf("wrote %d datagrams, want 3 fragments", n)
	}

	// The keepalive ping is framed as well and must still be recognised.
	if err := client.WritePing(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for wire.written.Load() != 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := wire.written.Load(); n != 4 {
		t.Fatalf("ping wrote %d datagrams in total, want 4", n)
	}
}

// A peer that does not frame the data channel must not smuggle payloads past
// the stub decoder: upstream drops packets without the no-compress byte.
func TestCompLzoNoStubRejectsUnframedPacket(t *testing.T) {
	client, peer, _ := newFramedPair(t, &ClientConfig{CompLZO: CompLzoNo}, &ClientConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// The peer has no comp-lzo, so its ping carries no stub byte.
	if err := peer.WritePing(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadIPPacket(ctx); err == nil {
		t.Fatal("unframed packet must be dropped")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read returned %v, want a timeout", err)
	}
}

// The stub head must be stripped before the ping check, otherwise keepalives
// would be handed to the IP stack as bogus packets.
func TestCompLzoNoStubKeepsPingOutOfStack(t *testing.T) {
	client, peer, _ := newFramedPair(t, &ClientConfig{CompLZO: CompLzoNo}, &ClientConfig{CompLZO: CompLzoNo})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := peer.WritePing(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadIPPacket(ctx); err == nil {
		t.Fatal("ping must not surface as an IP packet")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read returned %v, want a timeout", err)
	}
}

func TestInstallScriptOptionsStringCompLzoStub(t *testing.T) {
	options := InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA512, CompLzoNo, 0)
	if !strings.Contains(options, ",comp-lzo,") {
		t.Fatalf("comp-lzo no must be advertised like upstream: %s", options)
	}
	if !strings.Contains(options, "link-mtu 1544") {
		t.Fatalf("compression framing must be reflected in link-mtu: %s", options)
	}
	stub := InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA512, CompLzoNo, 1300)
	if !strings.Contains(stub, "comp-lzo,mtu-dynamic,") {
		t.Fatalf("stub framing and fragmentation must compose: %s", stub)
	}
	if !strings.Contains(stub, "link-mtu 1548") {
		t.Fatalf("fragment header must still grow link-mtu: %s", stub)
	}
}

func TestCompressionFramingHelpers(t *testing.T) {
	tests := []struct {
		compLZO string
		framing bool
		stub    bool
	}{
		{CompLzoYes, true, false},
		{CompLzoNo, true, true},
		{"", false, false},
	}
	for _, test := range tests {
		config := ClientConfig{CompLZO: test.compLZO}
		if got := config.compressionFraming(); got != test.framing {
			t.Fatalf("compressionFraming(%q) = %t, want %t", test.compLZO, got, test.framing)
		}
		if got := config.compressionStub(); got != test.stub {
			t.Fatalf("compressionStub(%q) = %t, want %t", test.compLZO, got, test.stub)
		}
	}
}
