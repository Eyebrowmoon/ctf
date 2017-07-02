#!/usr/bin/python
from decimal import Decimal
from pwn import *
import sys

f = open('Beale2.txt')
text = f.read()
f.close()

charset = "abcdefghijklmnopqrstuvwxyz0123456789{}"
arr = [106, 294, 403, 606, 762, 816, 218, 238, 308, 156, 317, 20, 447, 271, 561, 409, 623, 385, 288, 573, 665, 1, 108, 688, 707, 454, 560, 273, 25, 65, 849, 136, 311, 338, 468, 284, 684, 232]

seq = '1Poz9}l76D4bu8mkths{vAjxiNc0fqerygw352'.lower()
dic = {}

for c in text:
  if c in dic:
    dic[c] += 1
  else:
    dic[c] = 1

print dic

encoded_arr = [0.0306985711292929, 0.5068922333709739, 0.9506666408313629, 0.7463983030880548, 0.2626474863188886, 0.6844643909366914, 0.9830823317536876]
decrypted = ''

for f in encoded_arr:
  print "%.16f" % f

interval = 1.0 / len(seq)

for encoded in encoded_arr:
  for i in xrange(7):
    tmp = encoded / interval

    idx = int(tmp)
    encoded = tmp - idx

    decrypted += seq[idx]

  print decrypted

'''
encoded = 0
test = 'plus{'
for c in test:
  encoded += interval * seq.find(c)
  interval /= len(seq)

print encoded
'''
