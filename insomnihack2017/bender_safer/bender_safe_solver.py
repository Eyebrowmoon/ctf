import sys
OTP = str(raw_input())
print OTP
key = ""
mychar = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
key += OTP[0]
key += OTP[15]
if ord(OTP[7]) < ord('A'):
  key += chr(ord(OTP[7]) ^ 64)
else:
  key += chr(ord(OTP[7]) ^ 0x4B ^ 0x61 ^ 0xA)

if ord(OTP[3]) >= ord('A'):
  key += mychar[mychar.find(OTP[3]) + 10]
else :
  key += mychar[mychar.find(OTP[3]) - 10]

if ord(OTP[4]) >= ord('A'):
  key += mychar[mychar.find(OTP[4]) + 10]
else :
  key += mychar[mychar.find(OTP[4]) - 10]

leng = len(mychar)

key += mychar[(abs(ord(OTP[1]) - ord(OTP[2]))) % 35]
key += mychar[(abs(ord(OTP[5]) - ord(OTP[6]))) % 35]

if ord(OTP[8]) >= ord('A'):
  key += chr(ord(OTP[8]) ^ 0x4B ^ 0x61 ^ 0xA)
else:
  key += chr(ord(OTP[8]) ^ 64)

print key
