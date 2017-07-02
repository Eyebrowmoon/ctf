#!/usr/bin/python
from pwn import *
import os
import random

context.log_level = 'debug'

def random_string(size):
  res = ''
  for i in range(size):
    res += chr(random.randint(0,255))
  return res

target = './sample1'
p = process('./reeses')
f = open(target, 'rb')

print hex(os.path.getsize(target))
p.send(p32(os.path.getsize(target)))
p.send(f.read())

def do(action, size):
  p.send(chr(action))
  p.send(p32(size))
  p.send(random_string(size))

while True:
  try:
    action = random.randint(0,1)
    size = random.randint(1, 0x4000)
    do(action, size)
  except:
    break

# p.interactive()
p.close()
