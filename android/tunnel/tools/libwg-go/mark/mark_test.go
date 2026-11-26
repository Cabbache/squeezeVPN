package mark

import (
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeDev hands out queued packets on Read and records Writes.
type fakeDev struct {
	tun.Device
	in      [][]byte
	written [][]byte
}

func (d *fakeDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n < len(bufs) && len(d.in) > 0 {
		sizes[n] = copy(bufs[n][offset:], d.in[0])
		d.in = d.in[1:]
		n++
	}
	return n, nil
}

func (d *fakeDev) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		d.written = append(d.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (d *fakeDev) File() *os.File { return nil }

func sum(b []byte, init uint32) uint16 {
	s := init
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

// packet builds an IPv4 TCP (flags) or UDP packet with correct checksums.
func packet(proto byte, src, dst [4]byte, sport, dport uint16, flags byte, payload string) []byte {
	l4len := 8
	if proto == protoTCP {
		l4len = 20
	}
	p := make([]byte, 20+l4len+len(payload))
	p[0], p[8], p[9] = 0x45, 64, proto
	p[2], p[3] = byte(len(p)>>8), byte(len(p))
	copy(p[12:], src[:])
	copy(p[16:], dst[:])
	l4 := p[20:]
	l4[0], l4[1], l4[2], l4[3] = byte(sport>>8), byte(sport), byte(dport>>8), byte(dport)
	if proto == protoTCP {
		l4[12], l4[13] = 5<<4, flags
	} else {
		l4[4], l4[5] = byte(len(l4)>>8), byte(len(l4))
	}
	copy(l4[l4len:], payload)
	fill(p)
	return p
}

// fill computes the IP and TCP/UDP checksums from scratch.
func fill(p []byte) {
	p[10], p[11] = 0, 0
	v := sum(p[:20], 0)
	p[10], p[11] = byte(v>>8), byte(v)
	l4 := p[20:]
	at := 6
	if p[9] == protoTCP {
		at = 16
	}
	l4[at], l4[at+1] = 0, 0
	pseudo := uint32(be16(p[12:])) + uint32(be16(p[14:])) + uint32(be16(p[16:])) + uint32(be16(p[18:])) + uint32(p[9]) + uint32(len(l4))
	v = sum(l4, pseudo)
	if v == 0 && p[9] == protoUDP {
		v = 0xffff
	}
	l4[at], l4[at+1] = byte(v>>8), byte(v)
}

// checksumsOK recomputes both checksums and compares them with the packet's.
func checksumsOK(t *testing.T, p []byte) {
	t.Helper()
	c := append([]byte(nil), p...)
	fill(c)
	if string(c) != string(p) {
		t.Fatalf("checksums wrong after rewrite:\n got  %x\n want %x", p, c)
	}
}

var site = [4]byte{93, 184, 216, 34}

func readAll(m *Tun, d *fakeDev) [][]byte {
	var out [][]byte
	for len(d.in) > 0 {
		bufs, sizes := [][]byte{make([]byte, 2000)}, []int{0}
		n, _ := m.Read(bufs, sizes, 0)
		for i := 0; i < n; i++ {
			out = append(out, bufs[i][:sizes[i]])
		}
	}
	return out
}

func TestUntouchedFlowsAreMarkedAndRepliesRestored(t *testing.T) {
	asked := 0
	d := &fakeDev{}
	m := New(d, func(proto byte, src, dst [4]byte, sport, dport uint16) bool {
		asked++
		return dport == 443 // "untouched" app talks to 443, the browser to 8443
	})
	d.in = [][]byte{
		packet(protoTCP, phoneAddr, site, 40000, 443, 0x02, ""),               // SYN, untouched app
		packet(protoTCP, phoneAddr, site, 40000, 443, 0x18, "hello"),          // data on the same flow
		packet(protoTCP, phoneAddr, site, 40001, 8443, 0x02, ""),              // decrypted app
		packet(protoUDP, phoneAddr, site, 50000, 443, 0, "quic"),              // UDP, untouched app
		packet(protoUDP, phoneAddr, [4]byte{1, 1, 1, 1}, 50001, 53, 0, "dns"), // DNS: never asked
	}
	out := readAll(m, d)
	if asked != 3 {
		t.Fatalf("lookup asked %d times, want 3 (once per new flow, never for DNS)", asked)
	}
	wantSrc := [][4]byte{markAddr, markAddr, phoneAddr, markAddr, phoneAddr}
	for i, p := range out {
		if [4]byte(p[12:16]) != wantSrc[i] {
			t.Fatalf("packet %d: source %v, want %v", i, p[12:16], wantSrc[i])
		}
		checksumsOK(t, p)
	}

	// replies to the marked address get the interface address back
	reply := packet(protoTCP, site, markAddr, 443, 40000, 0x12, "")
	other := packet(protoTCP, site, phoneAddr, 8443, 40001, 0x12, "")
	m.Write([][]byte{reply, other}, 0)
	for i, p := range d.written {
		if [4]byte(p[16:20]) != phoneAddr {
			t.Fatalf("reply %d: destination %v, want the phone's address", i, p[16:20])
		}
		checksumsOK(t, p)
	}
}

func TestNewSynAsksAgainAndIdleFlowsAreForgotten(t *testing.T) {
	now := time.Unix(1000, 0)
	plain := true
	asked := 0
	d := &fakeDev{}
	m := New(d, func(byte, [4]byte, [4]byte, uint16, uint16) bool { asked++; return plain })
	m.now = func() time.Time { return now }

	d.in = [][]byte{packet(protoTCP, phoneAddr, site, 40000, 443, 0x02, "")}
	readAll(m, d)
	// the same port reused by another app: a new SYN asks again
	plain = false
	d.in = [][]byte{packet(protoTCP, phoneAddr, site, 40000, 443, 0x02, "")}
	if out := readAll(m, d); [4]byte(out[0][12:16]) != phoneAddr || asked != 2 {
		t.Fatalf("new SYN: asked %d, source %v", asked, out[0][12:16])
	}
	// idle for longer than a TCP flow lives: forgotten, the next packet asks again
	now = now.Add(tcpIdle + time.Minute)
	d.in = [][]byte{packet(protoTCP, phoneAddr, site, 40000, 443, 0x10, "x")}
	readAll(m, d)
	if asked != 3 {
		t.Fatalf("idle flow not forgotten: asked %d", asked)
	}
}

func TestOtherPacketsPassUntouched(t *testing.T) {
	d := &fakeDev{}
	m := New(d, func(byte, [4]byte, [4]byte, uint16, uint16) bool { return true })
	icmp := packet(protoUDP, phoneAddr, site, 1, 2, 0, "x")
	icmp[9] = 1 // ICMP
	v6 := make([]byte, 60)
	v6[0] = 0x60
	frag := packet(protoUDP, phoneAddr, site, 50000, 443, 0, "frag")
	frag[7] = 10 // a later fragment: no ports to look at
	udpNoSum := packet(protoUDP, phoneAddr, site, 50002, 443, 0, "nosum")
	udpNoSum[26], udpNoSum[27] = 0, 0
	for _, p := range [][]byte{icmp, v6, frag} {
		before := append([]byte(nil), p...)
		d.in = [][]byte{p}
		out := readAll(m, d)
		if string(out[0]) != string(before) {
			t.Fatalf("changed a packet it should leave alone: %x", before[:20])
		}
	}
	// UDP without a checksum keeps "no checksum"
	d.in = [][]byte{udpNoSum}
	out := readAll(m, d)
	if [4]byte(out[0][12:16]) != markAddr || out[0][26] != 0 || out[0][27] != 0 {
		t.Fatalf("UDP without checksum: %x", out[0][:28])
	}
}
