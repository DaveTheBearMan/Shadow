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
	ShadowVM := createCombinedVM()
	ShadowSocket := CreateRecieveSocket()
	ShadowChannel := make(chan ShadowPacket)

	go acceptPacket(ShadowSocket, ShadowVM, "UNK", ShadowChannel)

	// Anonymous function to shut down any socket files when done is recieved
	go func() {
		<-ctx.Done()
		ShadowSocket.Close()
	}()

	// Return channel for incoming packets
	return ShadowChannel
}

// Send takes a file descriptor, a destination address, and sends data after prefixing with [SHADOW]
func Send(fd int, destination net.IP, l4Proto string, l7Proto string, Data string) error {
	packetData := CreatePacket(destination, l4Proto, l7Proto, Data)
	ipv4Address := destination.To4()
	if ipv4Address == nil {
		return fmt.Errorf("destination is not IPv4: %v", destination)
	}

	socketAddress := &unix.SockaddrInet4{}
	copy(socketAddress.Addr[:], ipv4Address)

	return unix.Sendto(fd, packetData, 0, socketAddress)
}
