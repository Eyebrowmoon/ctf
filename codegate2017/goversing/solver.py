import angr, claripy

start = 0x401b40
target = 0x4021a8

to_avoid = [0x4020a6, 0x40209f, 0x4021dd, 0x4021ce, 0x40217f]

p = angr.Project('goversing', load_options={'auto_load_libs' : False})

init = p.factory.blank_state(addr = start)

userid = claripy.BVS('rax', 15 * 8)
userpw = claripy.BVS('rdx', 29 * 8)

init.memory.store(init.regs.rsp + 8, userid)
init.memory.store(init.regs.rsp + 0x10, 15)
init.memory.store(init.regs.rsp + 0x18, userpw)
init.memory.store(init.regs.rsp + 0x20, 15)

for i in xrange(15):
  a = init.memory.load(userid + i, 1)
  b = init.memory.load(userpw + i, 1)

  init.add_constraints(a > 0x20)
  init.add_constraints(b > 0x20)
  init.add_constraints(a < 0x7f)
  init.add_constraints(b < 0x7f)

pg = p.factory.path_group(init)
pg.explore(find = target, avoid = to_avoid)

print found.state.se.any_str(userid)
print found.state.se.any_str(userpw)
