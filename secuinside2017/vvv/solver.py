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

while True:
  try:
    p = process("./vvv")

    randval = random.randint(0, 0x100)
    for i in xrange(randval):
      length = random.randint(0, 0x100)
      s("\x17" * length + " ", False)

    length = random.randint(0, 0x100)
    s("\x17" * length, False)

    p.close()
  except:
    continue
