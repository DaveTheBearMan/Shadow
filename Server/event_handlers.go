package shadow

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Listen will open two sockets to listen for UDP and TCP packets respectively
func Listen(ctx context.Context) chan ShadowPacket {
	// Virtual Machines
	TCPVM := createTCPVM()
	TCPSocketFile := CreateRecieveSocket()
	UDPVM := createUDPVM()
	UDPSocketFile := CreateRecieveSocket()

	// Create a channel for listening to incoming packets
	socketChannel := make(chan ShadowPacket)
	go acceptPacket(TCPSocketFile, TCPVM, "TCP", socketChannel)
	go acceptPacket(UDPSocketFile, UDPVM, "UDP", socketChannel)

	// Anonymous function to shut down any socket files when done is recieved
	go func() {
		<-ctx.Done()
		TCPSocketFile.Close()
		UDPSocketFile.Close()
	}()

	// Return channel for incoming packets
	return socketChannel
}

// Send takes a file descriptor, a destination address, and sends data after prefixing with [SHADOW]
func Send(fd int, destination net.IP, Data string) error {
	Data = "[SHADOW]" + Data
	packetData := CreatePacket(destination, "TCP", "DNS", Data)
	ipv4Address := destination.To4()
	if ipv4Address == nil {
		return fmt.Errorf("destination is not IPv4: %v", destination)
	}

	socketAddress := &unix.SockaddrInet4{}
	copy(socketAddress.Addr[:], ipv4Address)

	return unix.Sendto(fd, packetData, 0, socketAddress)
}