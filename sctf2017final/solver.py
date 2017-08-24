from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p = process('./ruma')
# p = remote("52.78.27.112", 10001)

# gdb.attach(p, gdbscript=script)

DEBUG = True

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info("Received:" + response)
  return response

def s(msg, enter = True):
  msg = msg + "\n" if enter else msg
  p.send(msg)
  if DEBUG:
    log.info("Sent: " + msg)

p.interactive()
p.close()
