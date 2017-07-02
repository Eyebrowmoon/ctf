#!/usr/bin/python
from pwn import *

p = process('./memo')

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def set_index(index):
  r(">> ")
  p.sendline('1')

  r("Index: ")
  p.sendline(str(index))

def leave_msg(index, length, 

p.interactive()
p.close()
