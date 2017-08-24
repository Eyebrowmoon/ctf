#!/usr/bin/python

from pwn import *

# s = remote("52.198.232.90", 31337)
s = process("./omega_go")


for row in range(9):
    for i in range(19):
        for r in range(22):
            log.info(s.recvline())

        (s.sendline(chr(i + 0x41) + str(row + 1)))

for i in range(9):
    for r in range(22):
        log.info(s.recvline())
    (s.sendline(chr(i + 0x41) + str(10)))

"""
for i in range(8):
    for r in range(22):
        log.info(s.recvline())
    (s.sendline(chr(i + 0x41) + str(1)))

for r in range(22):
    log.info(s.recvline())

s.sendline("A3")

# s.interactive()

s.sendline("surrender")
log.info(s.recvline())
"""

gdb.attach(s)

s.interactive()
