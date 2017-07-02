import angr, simuvex, claripy

start = 0x400781

p = angr.Project("RamG_patch3.exe", load_options={'auto_load_libs' : False})

state = p.factory.blank_state(addr=start)

path = p.factory.path(state=state)

ex = angr.surveyors.Explorer(p, start=path, find=(0x40274d,))
r = ex.run()

print r.found[0].state.posix.dump(0)
