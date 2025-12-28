package shadow

import (
	"encoding/binary"

	"golang.org/x/net/bpf"
)

func createUDPFilter() []bpf.Instruction {
	outwardInterface, err := getOutwardIface()
	if err != nil {
		panic("Unable to get outward iface. Does ens3 match existing drivers?")
	}
	outwardMac := outwardInterface.HardwareAddr

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

		bpf.RetConstant{Val: 50}, // Accept
		bpf.RetConstant{Val: 0},  // Lightly optimized decline
	}
}

func createTCPFilter() []bpf.Instruction {
	outwardInterface, err := getOutwardIface()
	if err != nil {
		panic("Unable to get outward iface. Does ens3 match existing drivers?")
	}
	outwardMac := outwardInterface.HardwareAddr

	highValue := binary.BigEndian.Uint32(outwardMac[0:4])
	lowValue := binary.BigEndian.Uint16(outwardMac[4:6])

	const (
		// Ethernet
		hiMacOff  = 6
		hiMacSize = 4
		loMacOff  = 10
		loMacSize = 2

		// Sections
		ipProtoOff  = 23
		ipProtoSize = 1
		protoTCP    = 0x06

		// Magic bytes to match at *start of TCP payload*
		hiHeader = 0x5B534841 // [SHA
		loHeader = 0x444F575D // DOW]
	)

	return []bpf.Instruction{
		// Drop IPv6
		bpf.LoadAbsolute{Off: 12, Size: 2}, // 0x0800 when IPV4 in Eth Header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Drop frames we sent (match src MAC)
		bpf.LoadAbsolute{Off: hiMacOff, Size: hiMacSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: highValue, SkipTrue: 3},
		bpf.LoadAbsolute{Off: loMacOff, Size: loMacSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(lowValue), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Check for TCP
		bpf.LoadAbsolute{Off: ipProtoOff, Size: ipProtoSize}, // Ensure TCP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Calculate IPv4 Header Offset
		bpf.LoadMemShift{Off: 14},
		bpf.TXA{}, // Move that into RegA
		bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 14}, // Add length of EthHeader, so we can get to start of TCP packet
		bpf.StoreScratch{Src: bpf.RegA, N: 0},        // Store offset (Ethernet + IPv4) into Scratch 0
		bpf.TAX{},                                    // Write offset into X so we can use loadindirect to access TCP fields

		// Calculate TCP Header Offset
		bpf.LoadIndirect{Off: 12, Size: 1},                 // First 4 bits are the data offset. Trailing 4 are reserved
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4}, // 0b01010000 -> 0b00000101 (0x50 -> 0x05)
		bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4},        // Get length in bytes of TCP header
		bpf.LoadScratch{Dst: bpf.RegX, N: 0},               // Pull TCP header offset from earlier
		bpf.ALUOpX{Op: bpf.ALUOpAdd},                       // Add the IP header length to TCP header
		bpf.StoreScratch{Src: bpf.RegA, N: 0},              // Overwrite to have payload in scratch
		bpf.TAX{},

		// Read for shadow magic bytes at the calculated length
		bpf.LoadIndirect{Off: 0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: hiHeader, SkipTrue: 3},
		bpf.LoadIndirect{Off: 4, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: loHeader, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Calculate beginning of data when header is correct
		bpf.TXA{},
		bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 8},
		bpf.RetA{}, // Return beginning index of data within the packet
	}
}

func createCombinedFilter() []bpf.Instruction {
	outwardInterface, err := getOutwardIface()
	if err != nil {
		panic("Unable to get outward iface. Does ens3 match existing drivers?")
	}
	outwardMac := outwardInterface.HardwareAddr

	highValue := binary.BigEndian.Uint32(outwardMac[0:4])
	lowValue := binary.BigEndian.Uint16(outwardMac[4:6])

	const (
		// Ethernet
		hiMacOff  = 6
		hiMacSize = 4
		loMacOff  = 10
		loMacSize = 2

		// Sections
		ipProtoOff  = 23
		ipProtoSize = 1
		protoTCP    = 0x06
		protoUDP    = 0x11

		// Magic bytes to match at *start of TCP payload*
		hiHeader = 0x5B534841 // [SHA
		loHeader = 0x444F575D // DOW]
	)

	return []bpf.Instruction{
		// Drop IPv6
		bpf.LoadAbsolute{Off: 12, Size: 2}, // 0x0800 when IPV4 in Eth Header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Drop frames we sent (match src MAC)
		bpf.LoadAbsolute{Off: hiMacOff, Size: hiMacSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: highValue, SkipTrue: 3},
		bpf.LoadAbsolute{Off: loMacOff, Size: loMacSize},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(lowValue), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Drop unsupported protocols
		bpf.LoadAbsolute{Off: ipProtoOff, Size: ipProtoSize},        // Ensure TCP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP, SkipTrue: 3}, // Jump to TCP Calculation
		bpf.LoadAbsolute{Off: ipProtoOff, Size: ipProtoSize},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Calculate IPv4 Header Offset
		bpf.LoadMemShift{Off: 14},
		bpf.TXA{}, // Move that into RegA
		bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 14}, // Add length of EthHeader, so we can get to start of L4 packet
		bpf.StoreScratch{Src: bpf.RegA, N: 0},        // Store offset (Ethernet + IPv4) into Scratch 0
		bpf.TAX{},                                    // Write offset into X so we can use loadindirect to access L4 fields

		// Skip over TCP header calculations if we are working with UDP
		bpf.LoadAbsolute{Off: ipProtoOff, Size: ipProtoSize},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipTrue: 7}, // If it is not UDP, we know safely that it must be TCP BOA

		// Calculate TCP Header Offset
		bpf.LoadIndirect{Off: 12, Size: 1},                 // First 4 bits are the data offset. Trailing 4 are reserved
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4}, // 0b01010000 -> 0b00000101 (0x50 -> 0x05)
		bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4},        // Get length in bytes of TCP header
		bpf.LoadScratch{Dst: bpf.RegX, N: 0},               // Pull TCP header offset from earlier
		bpf.ALUOpX{Op: bpf.ALUOpAdd},                       // Add the IP header length to TCP header
		bpf.StoreScratch{Src: bpf.RegA, N: 0},              // Overwrite to have payload in scratch
		bpf.TAX{},
		bpf.Jump{Skip: 3}, // Jump over UDP offset update

		// Calculate UDP Header Offset
		bpf.LoadConstant{Dst: bpf.RegA, Val: 8}, // UDP has fixed headerlen of 8
		bpf.ALUOpX{Op: bpf.ALUOpAdd},
		bpf.TAX{}, // Move offset into RegX from RegA

		// Read for shadow magic bytes at the calculated length
		bpf.LoadIndirect{Off: 0, Size: 4}, // This will load from either the end of TCP header or end of IP header (UDP)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: hiHeader, SkipTrue: 3},
		bpf.LoadIndirect{Off: 4, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: loHeader, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// Calculate beginning of data when header is correct
		bpf.TXA{},
		bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 8},
		bpf.RetA{}, // Return beginning index of data within the packet
	}
}

func testTCPFilter(vm *bpf.VM) {
	testData := []byte{0x84, 0x70, 0xd7, 0xf6, 0xec, 0x12, 0xbc, 0x0f, 0xf3, 0x62, 0x57, 0x09, 0x08, 0x00, 0x45, 0x00, 0x00, 0x39, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x23, 0x5c, 0xa9, 0xfe, 0x17, 0x0c, 0x81, 0x15, 0x15, 0x43, 0x30, 0x39, 0x00, 0x16, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xfd, 0x5b, 0x00, 0x00, 0x5b, 0x53, 0x48, 0x41, 0x44, 0x4f, 0x57, 0x5d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74}
	outputFrameLen, err := vm.Run(testData)
	if err != nil {
		panic("Test filter failed")
	}
	if outputFrameLen <= 0 {
		panic("Test filter failed to pass any packets")
	}
}
