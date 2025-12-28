# Creating a Layer 7 Protocol with Raw Sockets

## How to use raw sockets, TLVs, legacy BPF, and basic cryptography to surpass host level firewalls and filtering.

The first step in creating your own networking protocol is understanding existing protocols, and what features they offer. For the sake of brevity, I will not reexplain TCP and UDP, but we will look at where data falls in specific bytes of their payloads for crafting our filters later on. 

The purpose for the creation of this protocol is as follows.

1. Expose a Go module that can be used by Red vs Blue competition tools to communicate around UFW, IPTables, FirewallCMD, SELINUX, and more.  
2. Understand how packets are created at the lowest level of networking  
3. Understand how filtering works at the lowest level of networking  
4. Create a protocol which is port and L4 protocol agnostic, such that it can still be routed through network routers and go through any exposed ports to reach embedded clients.

## A preface for all GoLang code in this blog post
There will be select code snippets with `...` put in place of logic, edge cases, or semantically clear examples that do not need additional code. An example of this would be:

```go
func checkErr(err Error) {
    ...
}
``` 
It is clear from basic Go knowledge that this function will check whether or not the error exists, and do some logic to alert the user and stop execution. 

In addition, common functions which an implementation or wrapper had to be created will recieve the same treatment. For example:
```go
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}
```
would simply become:
```go
func htons(i uint16) uint16 {
    ...
}
``` 
as it is clear that it is the same htons function as C, simply implemented in Go. 

## Initial Knowledge on BPF and Linux Sockets

To begin, it is important to cover what BPF actually is. BPF (or Berkeley Packet Filter) is a network tap which gives access to user space programs to provide a filter to the kernel for listening on the data link layer for network traffic. The filter that you provide is instructions to a virtual machine which are compiled JIT (just in time) for execution. A much more popular implementation built on top of the original BPF is eBPF, which is much more feature rich and well documented. If you would like to read more about either, the wikipedia page for [BPF which can be found here](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) has a much more succinct definition, and [eBPF has an article they wrote explaining eBPF.](https://ebpf.io/what-is-ebpf/) 

## Linux Sockets

To begin, we need to create a Raw Socket in Go which is capable of listening to all incoming traffic, with no initial filtering applied. The first step in this process is the actual raw socket, which is the same in Go as C functionality in Linux:
```C
socket(int *domain, int type, int protocol);
```

In order to create a raw socket, we need the following flags.

 - **Domain:** `AF_INET`
 - **Type:** `SOCK_RAW`
 - **Protocol:** `ETH_P_ALL`

Figuring out which flags to use is actually not trivial as you work your way up from the bottom. The best places to look are the man pages for [raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html) and [socket(7)](https://man7.org/linux/man-pages/man7/packet.7.html). There are a ton of possible flags though, and some of them are only defined in the header file for ethernet on linux [(see here)](https://github.com/torvalds/linux/blob/d26143bb38e2546fe6f8c9860c13a88146ce5dd6/include/uapi/linux/if_ether.h#L32-L165).

### Domain Argument
The parameter requiring a domain defines the socket family. The options for socket family can be viewed [within the header file for socket in linux here](https://github.com/torvalds/linux/blob/d26143bb38e2546fe6f8c9860c13a88146ce5dd6/include/linux/socket.h#L205-L310). In particular, the ones we care about are:
- `AF_INET`
- `AF_PACKET`

`AF` stands for **A**ddress **F**amily, while `INET` supports IPv4, and `PACKET` gives the raw packet (with ethernet header included). There are dozens of other supported address families including `AF_UNIX` (for Unix domain sockets), `AF_IPX` (Internetwork Packet Exchange), `AF_BLUETOOTH`, and more.  

If you wanted to support IPv6, you would need `AF_INET6`.

### Type Argument
There are a few options for the type of socket. The [man page contains many of them](https://man7.org/linux/man-pages/man2/socket.2.html), and what they are used for. The socket man page also includes some of the possible domain arguments.

There are two types that we concern ourselves with for this project: `SOCK_RAW` and `SOCK_DGRAM`.

#### SOCK_RAW Type
`SOCK_RAW` provides access to the bytes coming in across the wire in packets. There is no filtering, or garuntees for packets coming in across this type, and gives us access before the kernel does anything to it. This functionality is what allows this project to exist, as we can look at packets before firewalls have any impact upon them.

#### SOCK_DGRAM Type
`SOCK_DGRAM`, while we are not using it, can be useful for abstracting data the kernel can generate. There is an incredible diagram from a stackoverflow answer that covers the intersection of SOCK_RAW, SOCK_DGRAM, and domain arguments.

### Type and Domain Chart for Socket Interfaces
On stack overflow, a random person created a chart correlating a lot of this data. I have included the chart below and the [answer can be read here](https://stackoverflow.com/a/78497916) (it mostly explains the chart, which I will quote below)

> Green color means when sending/receiving one has to take care of creating/interpreting the headers in the user space application. Blue color means, it's sufficient to set/get the correct values in an imported sockaddr struct and let the socket interface do the thing.
> 
> Red/Orange/Yellow colors are for visual distinction only.

![Diagram of socket interface and layers](https://i.sstatic.net/kZHNpa1b.png)

If it has not become clear up to this point, there is a lot of documentation to review, and public answers. The usage of AI can be helpful, but it will often lead you astray as it recommends various solutions from its sample that can be wildly over complicated or not include the simpler, built in functionality to do something. It will also fight you on crafting raw TCP packets, as it thinks of it as potentially malicious. 

### Protocol Argument
For most applications, we are going to use ETH_P_ALL as the protocol. All the potential arguments can be found in the [header file here](https://github.com/torvalds/linux/blob/d26143bb38e2546fe6f8c9860c13a88146ce5dd6/include/uapi/linux/if_ether.h#L134-L165). You'll notice the protocol we chose has the comment:
```C
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
```
This is a good thing to see when you are trying to circumvent firewalls.

Most of the protocols are self explanatory, or the comments cover which packets they will include.

## GoLang Sockets
In Go, there are wrapper functions to abstract the calls. For example, to generate our 