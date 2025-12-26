# Shadow Packet
Super basic raw sockets implementation with BPF filtering. Data is not sent back to hosts, see [Keydra](https://github.com/DaveTheBearMan/Keydra) for a more complex raw sockets system with a custom packet type built on top UDP.


### What is Shadow
Shadow allows a client to listen to incoming traffic on the outward facing interface for any UDP packets not sent by the host, with the prefix `[SHADOW]` in the data section. The port, destination address, source address, etc, does not matter. Any data following the prefix will be run as a command. 

### How to use shadow
The dropper script install.sh will create a malicious service called `dbus-org.freedesktop.isolate1.service` that begins immediately and starts on boot. The binary is located at `/etc/ntpsvc/timesync.d`. The uninstall.sh script can be used to remove from a system.

### Examples
For more examples, look in the examples directory for installation guides and usage techniques.