from pwn import *

initvec = [0, 0, 0, 0]

id_arr = [0x0007070405040007, 0x0504030606000204, 0x0106000106030004, 0x0305070106000207, 0x0501000106000204, 0x0707070405040306, 0x0103000405040007, 0x0704060603030605]

pw_arr = [0x5d6a345c1b2e5612, 0x6f34671c5b0f2973, 0x543570193a1e5011, 0x0000002e472d453f]

def xor(idx):
  idx1 = idx / 8
  idx2 = idx % 8

  result = ord(p64(id_arr[idx1])[idx2])

  bit3 = result & 0x1
  bit2 = (result & 0x2) >> 1
  bit1 = (result & 0x4) >> 2

  initvec[1] = initvec[0]
  initvec[2] = initvec[1]
  initvec[3] = initvec[2]

  initvec[0] = bit1 ^ 1

bitvec = []

for i in xrange(0x40):
  xor(i)
  bitvec.append(initvec[0])

bitvec = map(str, bitvec)

binary = "".join(bitvec)

user_id = hex(int(binary, 2))[2:].decode("hex")

print user_id

def xor2(idx):
  idx1 = idx / 8
  idx2 = idx % 8

  result = p64(pw_arr[idx1])[idx2]

  id_chr = user_id[idx2]

  return chr(ord(id_chr) ^ ord(result))

user_pw = ""

for i in xrange(0x1d):
  user_pw += xor2(i)

print user_pw
