package procinfo

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Conn is one socket owned by a process.
type Conn struct {
	PID    uint32 `json:"pid"`
	Proto  string `json:"proto"` // tcp | tcp6 | udp | udp6
	Local  string `json:"local"`
	Remote string `json:"remote,omitempty"`
	State  string `json:"state,omitempty"`
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	errInsufficient     = 122
)

var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
	7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

func table(p *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(16 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		if r == 0 {
			return buf[:size], nil
		}
		if r != errInsufficient {
			return nil, fmt.Errorf("%s: error %d", p.Name, r)
		}
	}
	return nil, fmt.Errorf("%s: table keeps growing", p.Name)
}

func port(v uint32) uint16 { return uint16(v>>8&0xff) | uint16(v&0xff)<<8 } // network byte order in low 16 bits

// Connections returns sockets owned by any of pids.
func Connections(pids []uint32) ([]Conn, error) {
	want := map[uint32]bool{}
	for _, p := range pids {
		want[p] = true
	}
	var out []Conn
	le := binary.LittleEndian

	if b, err := table(procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPIDAll); err == nil && len(b) >= 4 {
		n := le.Uint32(b)
		const row = 24
		for i := uint32(0); i < n && int(4+(i+1)*row) <= len(b); i++ {
			r := b[4+i*row:]
			pid := le.Uint32(r[20:])
			if !want[pid] {
				continue
			}
			la := netip.AddrFrom4([4]byte(r[4:8]))
			ra := netip.AddrFrom4([4]byte(r[12:16]))
			out = append(out, Conn{PID: pid, Proto: "tcp", State: tcpStates[le.Uint32(r)],
				Local:  netip.AddrPortFrom(la, port(le.Uint32(r[8:]))).String(),
				Remote: netip.AddrPortFrom(ra, port(le.Uint32(r[16:]))).String()})
		}
	}
	if b, err := table(procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPIDAll); err == nil && len(b) >= 4 {
		n := le.Uint32(b)
		const row = 56
		for i := uint32(0); i < n && int(4+(i+1)*row) <= len(b); i++ {
			r := b[4+i*row:]
			pid := le.Uint32(r[52:])
			if !want[pid] {
				continue
			}
			la := netip.AddrFrom16([16]byte(r[0:16]))
			ra := netip.AddrFrom16([16]byte(r[24:40]))
			out = append(out, Conn{PID: pid, Proto: "tcp6", State: tcpStates[le.Uint32(r[48:])],
				Local:  netip.AddrPortFrom(la, port(le.Uint32(r[20:]))).String(),
				Remote: netip.AddrPortFrom(ra, port(le.Uint32(r[44:]))).String()})
		}
	}
	if b, err := table(procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPID); err == nil && len(b) >= 4 {
		n := le.Uint32(b)
		const row = 12
		for i := uint32(0); i < n && int(4+(i+1)*row) <= len(b); i++ {
			r := b[4+i*row:]
			pid := le.Uint32(r[8:])
			if !want[pid] {
				continue
			}
			la := netip.AddrFrom4([4]byte(r[0:4]))
			out = append(out, Conn{PID: pid, Proto: "udp", Local: netip.AddrPortFrom(la, port(le.Uint32(r[4:]))).String()})
		}
	}
	if b, err := table(procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPID); err == nil && len(b) >= 4 {
		n := le.Uint32(b)
		const row = 28
		for i := uint32(0); i < n && int(4+(i+1)*row) <= len(b); i++ {
			r := b[4+i*row:]
			pid := le.Uint32(r[24:])
			if !want[pid] {
				continue
			}
			la := netip.AddrFrom16([16]byte(r[0:16]))
			out = append(out, Conn{PID: pid, Proto: "udp6", Local: netip.AddrPortFrom(la, port(le.Uint32(r[20:]))).String()})
		}
	}
	return out, nil
}
