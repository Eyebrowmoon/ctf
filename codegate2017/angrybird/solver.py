import angr, simuvex, claripy

start = 0x4007c2
target = 0x404fab

avoid = []

f = open('avoid','r')

while True:
  line = f.readline()
  if not line:
    break
  avoid_addr = int(line.split()[0][:-1], 16)
  avoid.append(avoid_addr)

f.close()

p = angr.Project('angrybird', load_options={'auto_load_libs' : False})

state = p.factory.blank_state(addr = start)
path = p.factory.path(state = state)

ex = angr.surveyors.Explorer(p, start = path, find = target, avoid = avoid)
r = ex.run()

print r.found[0].state.posix.dumps(0)
