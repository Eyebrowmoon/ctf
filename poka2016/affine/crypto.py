#!/usr/bin/python

from Crypto.Util.number import *
from Crypto.PublicKey import RSA

flag = open('flag.txt', 'r').read().strip()
tail = open('tiny_secret.txt', 'r').read().strip() # 9 printable string
flag_new = flag[:-9] + tail + flag[-1]

assert len(flag) == len(flag_new)

flag = bytes_to_long(flag)
flag_new = bytes_to_long(flag_new)

privkey = RSA.generate(1024, e = 3)
pubkey  = privkey.publickey()
e = 3
n = getattr(privkey.key, 'n')
d = getattr(privkey.key, 'd')

print pubkey.exportKey()

r = flag_new - flag
IMP = n - r**(e**2)
if IMP > 0:
	enc_1 = pow(flag, e, n)
	enc_2 = pow(flag_new, e, n)
	print 'enc_1 =', enc_1
	print 'enc_2 =', enc_2
