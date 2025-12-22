package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"

	"golang.org/x/net/bpf"
)

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// This is some AI nonsense, but I prompted it to
// find the interface regardless of whether or not
// something like net.Dial(8.8.8.8:80) would work,
// in other words, we dont need to do any connecting
// to make sure that we can get the outward interface
func getOutwardIface() ([]byte, error) {
	// Open net route file
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Open scanner
	sc := bufio.NewScanner(f)
	if !sc.Scan() { // header
		return nil, errors.New("empty /proc/net/route")
	}

	// Iterate until we find an interface who owns the default route
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		ifaceName := fields[0]
		dest := fields[1]
		if dest == "00000000" { // default route
			ifc, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, err
			}

			return ifc.HardwareAddr, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("no default route found")
}

func createFilter() []bpf.Instruction {
	outwardMac, err := getOutwardIface()
	if err != nil {
		panic("Unable to get outward iface. Does ens3 match existing drivers?")
	}
	highValue := binary.BigEndian.Uint32(outwardMac[0:4]) // High bits (Val supports 32 bits only)
	lowValue := binary.BigEndian.Uint16(outwardMac[4:6])  // Low bits

	const (
		// Mac address (High and low)
		hiMacOff  = 6
		hiMacSize = 4

		loMacOff  = 10
		loMacSize = 2

		// Ethernet type
		ethTypeOff  = 12
		ethTypeSize = 2
		ethIPv4     = 0x0800

		// IP protocol
		ipProtoOff  = 23 // 14 (eth) + 9 (IPv4 protocol field)
		ipProtoSize = 1
		protoUDP    = 0x11 // UDP is 17

		// UDP Data
		hiData   = 42
		loData   = 46
		dataSize = 4
		hiHeader = 0x5B534841 // [SHA
		loHeader = 0x444F575D // DOW]
	)

	return []bpf.Instruction{
		// // If we sent the packet, drop it.
		// The reason we do this is so that if we have P2P
		// shadow packets, we dont want to duplicate
		bpf.LoadAbsolute{Off: hiMacOff, Size: hiMacSize},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: highValue, SkipTrue: 11},
		bpf.LoadAbsolute{Off: loMacOff, Size: loMacSize},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(lowValue), SkipTrue: 9},

		// If EtherType is not Ipv4, drop packet
		bpf.LoadAbsolute{Off: ethTypeOff, Size: ethTypeSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: ethIPv4, SkipTrue: 7},

		// If EtherType is not Udp, drop packet
		bpf.LoadAbsolute{Off: ipProtoOff, Size: ipProtoSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoUDP, SkipTrue: 5},

		// If Packet doesnt contain [SHADOW] header, drop packet
		bpf.LoadAbsolute{Off: hiData, Size: dataSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: hiHeader, SkipTrue: 3},
		bpf.LoadAbsolute{Off: loData, Size: dataSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: loHeader, SkipTrue: 1},

		bpf.RetConstant{Val: 1500}, // Accept
		bpf.RetConstant{Val: 0},    // Lightly optimized decline
	}
}
