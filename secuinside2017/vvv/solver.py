from pwn import *
import random

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# gdb.attach(p)

# p = remote("localhost", 4924)
# p = remote("13.124.134.94", 8888)

DEBUG = True

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def s(msg, enter = True):
  msg = msg + "\n" if enter else msg
  p.send(msg)
  if DEBUG:
    log.info("Sent: " + msg)

p = process("./vvv")

s("\x17", False)

p.interactive()
p.close()

