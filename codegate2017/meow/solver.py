#!/usr/bin/python
from pwn import *

a = 0x618F652224A9469F
b = 0x14B97D8EE7DE0DA8

print (p64(a) + p64(b)).encode("hex")
