#!/usr/bin/python
import sys
import os

from pwn import *

if not sys.argv[1]:
    sys.argv[1] = 9345

with open('awsno', 'rb') as fi:
    content = fi.read()
    with open('awsno_patch', 'wb') as fo:
        fo.write(content.replace('\x41\xb9\x81\x24\x00\x00', '\x41\xb9'+p32(int(sys.argv[1]))))

os.system('chmod +x awsno_patch')
os.execv('./awsno_patch', ['./awsno_patch'])
