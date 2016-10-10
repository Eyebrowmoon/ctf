#!/home/ebmoon/.virtualenvs/angr-pypy/bin/python

import angr
import simuvex
import struct

DEBUG = True

p64 = lambda x: struct.pack("<Q", x)
u64 = lambda x: struct.unpack("<Q", x)

def p(msg):
  print "[*] %s" % msg

def main():
  arch = "ppc"
  p = angr.Project("flame", use_sim_procedures = False)

  """
  start = 0x1000078c
  fail = 0x10000964
  find = 0x10000944

  init = p.factory.block_state(addr=main, load_options={'auto_load_libs': False})

  pg = p.factory.path_group(init)
  ex = pg.explore(find = find, avoid = fail)

  final = ex.found[0].state
  flag = final.posix.dumps(0)

  print flag
  """

if __name__ == '__main__':
  main()
