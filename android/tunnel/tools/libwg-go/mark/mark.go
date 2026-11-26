/* SPDX-License-Identifier: Apache-2.0
 *
 * squeezeVPN addition (not in upstream wireguard-android).
 */

// Package mark lets the server tell apart connections of apps whose traffic must stay untouched.
package mark

import (
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Connections of apps whose traffic the server must leave untouched (no HTTPS decryption, no image
// shrinking) leave the phone with this tunnel address instead of the interface's own; the server
// relays everything from it as is. Replies to it are given back the interface address.
var (
	phoneAddr = [4]byte{10, 8, 0, 2}
	markAddr  = [4]byte{10, 8, 0, 3}
)

const (
	protoTCP = 6
	protoUDP = 17
	tcpIdle  = 10 * time.Minute
	udpIdle  = 3 * time.Minute
)

type flowKey struct {
	proto        byte
	sport, dport uint16
	dst          [4]byte
}

type flowState struct {
	plain bool
	seen  time.Time
}

// LookupFunc says whether a new connection belongs to an app whose traffic stays untouched.
type LookupFunc func(proto byte, src, dst [4]byte, sport, dport uint16) bool

// Tun wraps the real tun device: it marks connections of "untouched" apps (see markAddr).
type Tun struct {
	tun.Device
	lookup LookupFunc
	now    func() time.Time

	mu        sync.Mutex
	flows     map[flowKey]*flowState
	lastSweep time.Time
}

// New wraps dev; lookup is asked once per new connection.
func New(dev tun.Device, lookup LookupFunc) *Tun {
	return &Tun{Device: dev, lookup: lookup, now: time.Now, flows: make(map[flowKey]*flowState)}
}

func (m *Tun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := m.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		m.outgoing(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

func (m *Tun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		incoming(b[offset:])
	}
	return m.Device.Write(bufs, offset)
}

// outgoing (phone -> tunnel): rewrites the source of untouched flows to markAddr.
func (m *Tun) outgoing(p []byte) {
	proto, l4, ok := parse(p)
	if !ok || [4]byte(p[12:16]) != phoneAddr {
		return
	}
	sport, dport := be16(l4[0:]), be16(l4[2:])
	if proto == protoUDP && dport == 53 {
		return // DNS is never decrypted: no need to ask who sent it
	}
	key := flowKey{proto: proto, sport: sport, dport: dport, dst: [4]byte(p[16:20])}
	syn := proto == protoTCP && l4[13]&0x12 == 0x02 // SYN without ACK: a new connection

	now := m.now()
	m.mu.Lock()
	m.sweep(now)
	f := m.flows[key]
	m.mu.Unlock()
	if f == nil || syn {
		f = &flowState{plain: m.lookup(proto, phoneAddr, key.dst, sport, dport)}
		m.mu.Lock()
		m.flows[key] = f
		m.mu.Unlock()
	}
	f.seen = now
	if f.plain {
		setAddr(p, proto, l4, 12, markAddr)
	}
}

// incoming (tunnel -> phone): replies to markAddr go back to the interface address.
func incoming(p []byte) {
	proto, l4, ok := parse(p)
	if ok && [4]byte(p[16:20]) == markAddr {
		setAddr(p, proto, l4, 16, phoneAddr)
	}
}

// sweep forgets idle flows, at most every 30 s. Caller holds mu.
func (m *Tun) sweep(now time.Time) {
	if now.Sub(m.lastSweep) < 30*time.Second {
		return
	}
	m.lastSweep = now
	for k, f := range m.flows {
		idle := udpIdle
		if k.proto == protoTCP {
			idle = tcpIdle
		}
		if now.Sub(f.seen) > idle {
			delete(m.flows, k)
		}
	}
}

// parse returns the protocol and the TCP/UDP header of an unfragmented (or first-fragment) IPv4
// TCP/UDP packet; ok is false for anything else (IPv6, ICMP, later fragments, truncated packets).
func parse(p []byte) (proto byte, l4 []byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	proto = p[9]
	if ihl < 20 || be16(p[6:])&0x1fff != 0 {
		return 0, nil, false
	}
	need := 8
	if proto == protoTCP {
		need = 20
	} else if proto != protoUDP {
		return 0, nil, false
	}
	if len(p) < ihl+need {
		return 0, nil, false
	}
	return proto, p[ihl:], true
}

// setAddr replaces the IPv4 address at `at` (12 = source, 16 = destination) and updates the IP and
// TCP/UDP checksums incrementally (RFC 1624), as both cover the address.
func setAddr(p []byte, proto byte, l4 []byte, at int, addr [4]byte) {
	var old [4]byte
	copy(old[:], p[at:at+4])
	copy(p[at:at+4], addr[:])
	for w := 0; w < 4; w += 2 {
		o, n := be16(old[w:]), be16(addr[w:])
		fixSum(p[10:], o, n)
		switch proto {
		case protoTCP:
			fixSum(l4[16:], o, n)
		case protoUDP:
			if be16(l4[6:]) != 0 { // 0 = no checksum
				fixSum(l4[6:], o, n)
				if be16(l4[6:]) == 0 {
					l4[6], l4[7] = 0xff, 0xff // a computed 0 is sent as 0xffff in UDP
				}
			}
		}
	}
}

// fixSum updates the checksum at c[0:2] for one 16-bit word changing from o to n: HC' = ~(~HC + ~o + n).
func fixSum(c []byte, o, n uint16) {
	s := uint32(^be16(c)) + uint32(^o) + uint32(n)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	v := ^uint16(s)
	c[0], c[1] = byte(v>>8), byte(v)
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
