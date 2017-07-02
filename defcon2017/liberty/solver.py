#!/usr/bin/python
from pwn import *
import os

os.system('ps -aux | grep "./liberty localhost" > process_list')

f = open('process_list')
text = f.read()
f.close()

pid = int(text.split()[1])

with open('/proc/%d/maps' % pid, "r") as f:
  lines = f.readlines()

for line in lines:
  print line

  if line.find('rwxp') > 0:
    addr = line.split()[0][:8]
    addr_int = int(addr, 16) - 0x100000000

    os.system('./ptrace %d %d' % (pid, addr_int))
    os.system('mv dump dumps/dump_%s' % addr)
