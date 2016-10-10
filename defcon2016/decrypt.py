#!/usr/bin/python

import sys
import ctypes

DWORD = ctypes.c_uint32

arr = [1,2,3,4]

UINT_MAX = 1 << 32

b_lefts = []
a_lefts = []

def encrypt(a, b):
  trash = 0x7CBF26C0
  add_term = 0x160d0365

  for i in range(0x40):
    b_idx = (trash >> 11) & 3
    b_left = (trash + arr[b_idx]) % UINT_MAX
    b_right = (a + ((a << 4) ^ (a >> 5))) % UINT_MAX
    b = (b -  (b_left ^ b_right)) % UINT_MAX

    trash = (trash + add_term) % UINT_MAX

    a_idx = trash & 3
    a_left = (trash + arr[a_idx]) % UINT_MAX
    a_right = (b + ((b << 4) ^ (b >> 5))) % UINT_MAX
    a = (a - (a_left ^ a_right)) % UINT_MAX

    b_lefts.append(b_left)
    a_lefts.append(a_left)
 
    #print hex(b_left), hex(a_left), "--", hex(b), hex(a)

  #print ("Result: " + hex(a) + ", " + hex(b))
  
  return (a, b)

def decrypt(a, b):

  encrypt(1, 2) # To construct lefts
  
  for level in range(0x40):
    n = 0x40 - level - 1
    #print n
 
    a_left = a_lefts[n]
    a_right = (b + ((b << 4) ^ (b >> 5))) % UINT_MAX
    a = (a + (a_left ^ a_right)) % UINT_MAX

    b_left = b_lefts[n]
    b_right = (a + ((a << 4) ^ (a >> 5))) % UINT_MAX
    b = (b + (b_left ^ b_right)) % UINT_MAX

    #print hex(a), hex(b)
  
  return (a, b)

#result = encrypt(0x3d41591, 0xab97a0d1)
result = decrypt(0x7, 0x20)
print str(result[0]), str(result[1])
