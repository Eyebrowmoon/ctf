import angr, simuvex, claripy

start = 0x4012b7

p = angr.Project("babymisc", load_options={'auto_load_libs' : False})

state = p.factory.blank_state(addr=start)

path = p.factory.path(state=state)

ex = angr.surveyors.Explorer(p, start=path, find=(0x4012e7,))
r = ex.run()

print r.found[0].state.posix.dump(0)
