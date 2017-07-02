import angr, simuvex, claripy
import sys
import os


for i in xrange(1, 102):
  filename = "prob" + str(i)

  os.system('objdump -d ' + filename + ' | grep "0x1,%eax" | grep "mov" > addr')

  f = open('addr')
  addr = int(f.readline().split()[0][:-1], 16)
  f.close()

  target = addr

  p = angr.Project(filename, load_options={'auto_load_libs' : False})

  argv1 = angr.claripy.BVS('argv1', 0x100)
  init = p.factory.entry_state(args=[filename, argv1])
  pg = p.factory.path_group(init)

  pg.explore(find = target)

  print pg.found[0].state.se.any_str(argv1)
