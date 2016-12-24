#!/usr/bin/python

big = [112, 3, 88, 4, 90, 5, 90, 86, 4, 97, 124, 5, 89, 2, 3, 4, 22, 100, 38, 110]
small = [0, 0, 0, 0, 0, 0]

for i in xrange(6):
  b = big[small[i]] ^ small[i]
  big[small[i]] = b

print big
