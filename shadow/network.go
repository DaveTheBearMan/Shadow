package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/net/bpf"
)

var (
	mtu = 1500
)

func createSocket() *os.File {
	// Get a file descriptor and open a raw socket for all incoming packets
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(fmt.Sprintf("Unable to open file for socket, %v", err))
	}
	return os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
}

func acceptPacket(socketFile *os.File, vm *bpf.VM, socketProtocol string, packetChannel chan shadowPacket) error {
	for {
		// Read to buffer and create a frame
		frame := make([]byte, mtu)
		numRead, err := socketFile.Read(frame)

		// Check for failed packets and empty packets
		if err != nil {
			fmt.Printf("Unable to read buffer: %v", err)
			continue
		}
		if numRead == 0 {
			fmt.Printf("Empty packet recieved")
			continue
		}

		// Run the VM with instructions
		dataBeginIndex, err := vm.Run(frame)
		if err != nil {
			panic(fmt.Sprintf("failed to accept Ethernet frame: %v", err))
		}
		if dataBeginIndex > 0 {
			assembledFrame := shadowPacket{
				sourceAddr: frame[26:30],
				sourceMac:  frame[6:12],

				destAddr: frame[30:34],
				destMac:  frame[0:6],
				proto:    socketProtocol,

				data: bytes.Trim(frame[dataBeginIndex:], "\x00"),
			}
			packetChannel <- assembledFrame
		}
	}
}

func createTCPVM() *bpf.VM {
	// Create TCP BPF VM
	TCPBPFFilter := createTCPFilter()
	TCPVM, err := bpf.NewVM(TCPBPFFilter)
	if err != nil {
		panic(fmt.Sprintf("failed to load TCP BPF program: %v", err))
	}

	// TCP Testing
	testTCPPacket(TCPVM)

	return TCPVM
}

func createUDPVM() *bpf.VM {
	// Create TCP BPF VM
	UDPBPFFilter := createUDPFilter()
	UDPVM, err := bpf.NewVM(UDPBPFFilter)
	if err != nil {
		panic(fmt.Sprintf("failed to load TCP BPF program: %v", err))
	}

	// No testing for UDP yet

	return UDPVM
}
