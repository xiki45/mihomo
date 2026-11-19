package outbound

import "testing"

func TestOpenVPNStackMTU(t *testing.T) {
	tests := []struct {
		name   string
		mtu    int
		mssFix int
		want   int
	}{
		{name: "defaults", mtu: 0, mssFix: 0, want: 1500},
		{name: "explicit mtu", mtu: 1400, mssFix: 0, want: 1400},
		{name: "mss-fix clamps stack mtu", mtu: 1500, mssFix: 1200, want: 1200},
		{name: "mss-fix above mtu is ignored", mtu: 1200, mssFix: 1400, want: 1200},
		{name: "mss-fix without mtu keeps default bounds", mtu: 0, mssFix: 1300, want: 1300},
	}
	for _, test := range tests {
		if got := openVPNStackMTU(test.mtu, test.mssFix); got != test.want {
			t.Fatalf("%s: openVPNStackMTU(%d, %d) = %d, want %d", test.name, test.mtu, test.mssFix, got, test.want)
		}
	}
}
