#!/usr/bin/python

from pwn import *

DEBUG = True

p = remote("141.223.175.211", 4444)
#p = remote("easier_55605f781f413a2b699377ced27617f0.quals.shallweplayaga.me", "8989")

arr = [1,2,3,4]

UINT_MAX = 1 << 32

b_lefts = []
a_lefts = []

def recv_until(s):
  result = p.recvuntil("\n")
  if DEBUG:
    log.info(result);

def toString(tup):
  return str(tup[0]) + " " + str(tup[1])

def construct_lefts():
  trash = 0x7CBF26C0
  add_term = 0x160d0365

  for i in range(0x40):
    b_idx = (trash >> 11) & 3
    b_left = (trash + arr[b_idx]) % UINT_MAX
 
    trash = (trash + add_term) % UINT_MAX

    a_idx = trash & 3
    a_left = (trash + arr[a_idx]) % UINT_MAX

    b_lefts.append(b_left)
    a_lefts.append(a_left)

def encrypt(a, b):
  for i in range(0x40):
    b_left = b_lefts[i]
    b_right = (a + ((a << 4) ^ (a >> 5))) % UINT_MAX
    b = (b -  (b_left ^ b_right)) % UINT_MAX

    a_left = a_lefts[i]
    a_right = (b + ((b << 4) ^ (b >> 5))) % UINT_MAX
    a = (a - (a_left ^ a_right)) % UINT_MAX

    #print hex(b_left), hex(a_left), "--", hex(b), hex(a)

  #print ("Result: " + hex(a) + ", " + hex(b))
  
  return (a, b)

def decrypt(a, b):
  for level in range(0x40):
    n = 0x40 - level - 1
 
    a_left = a_lefts[n]
    a_right = (b + ((b << 4) ^ (b >> 5))) % UINT_MAX
    a = (a + (a_left ^ a_right)) % UINT_MAX

    b_left = b_lefts[n]
    b_right = (a + ((a << 4) ^ (a >> 5))) % UINT_MAX
    b = (b + (b_left ^ b_right)) % UINT_MAX

  return (a, b)

def send_pair(a, b):
  dec = decrypt(a, b)
  p.sendline(toString(dec))

def send_seq(seq):
  s = " ".join(seq)
  p.sendline(s)

construct_lefts()

recv_until("\n")
p.sendline("5 5 5 5")

send_pair(1, 3)

send_pair(1, 2040)
send_seq(["0"] * 2040)

send_pair(5, 1 << 8)
send_pair(2, 0)

send_pair(1, 2040)
send_seq(["AAAA"] * 2040)

send_pair(5, 2 << 8)

p.interactive()

p.close()
