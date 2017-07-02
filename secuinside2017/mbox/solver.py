import angr
import claripy

from ctypes import *

libc = CDLL('libc.so.6')

rand_values = []
libc.srand(c_int(60516051))


def get_rand_value(idx):
    while len(rand_values) <= idx:
        rand_values.append(libc.rand())
    return rand_values[idx]

# Initial state setting
b = angr.Project('m-box', load_options={'auto_load_libs': False})

vec = claripy.BVS('input', 8*81)
start = b.factory.blank_state(addr=0x400a3f)
start.memory.store(0x603c60, vec)


# Hook rand call
def srand(state):
    state.memory.store(0xcafebabe, claripy.BVV(0, 8*1))

b.hook(0x400b0a, srand, length=5)


def rand(state):
    cnt = state.se.any_int(state.memory.load(0xcafebabe, 1))
    state.memory.store(0xcafebabe, claripy.BVV(cnt+1, 8*1))
    state.regs.rax = claripy.BVV(get_rand_value(cnt), 8*8)

b.hook(0x400b2a, rand, length=5)


# Symbolic execution
pg = b.factory.path_group(start)
pg.explore(
    find=0x4014ab,
    avoid=[
        0x400a5e,
        0x401407,
        0x401497,
    ]
)

print '[+] Path Found - Calculating Determinant...'

original_state = pg.found[0].state
tmp_state = original_state.copy()

mem = [[tmp_state.memory.load(0x603c60 + y*9 + x, 1).zero_extend(8*7) for x in range(9)] for y in range(9)]

def inverse(mat_):
  mat = [[mat_[i][j] for j in range(9)] for i in range(9)]
  inv = [[claripy.BVV(1.0, 8*8) if x == y else claripy.BVV(0.0, 8*8) for x in range(9)] for y in range(9)]

  for i in range(9):
    for j in range(9):
      mat[i][j] += mat_[i][j]

  for i in range(9):
    for j in range(9):
      mat[i][j] = mat[0][j] + mat[i][j]
      inv[i][j] = inv[0][j] + inv[i][j]

  for i in range(9):
    pivot = mat[i][i]

    for j in range(9):
      mat[i][j] = mat[i][j] / pivot
      inv[i][j] = inv[i][j] / pivot

    for j in range(9):
      if i != j:
        coeff = mat[i][j]

        for k in range(9):
          mat[j][k] = mat[j][k] - mat[i][k] * coeff
          inv[j][k] = inv[j][k] - inv[i][k] * coeff

  for i in range(9):
    for j in range(9):
      entry = inv[i][j] + 0.000001

      if entry - int(entry) > 0.00001:
        return 0

  return 1

def determinant(lvl, cols):
    if lvl == 8:
        return mem[lvl][cols[0]]
    result = claripy.BVV(0, 8*8)
    for (i, col) in enumerate(cols):
        if i % 2 == 1:
            result -= mem[lvl][col] * determinant(lvl+1, cols[:i]+cols[i+1:])
        else:
            result += mem[lvl][col] * determinant(lvl+1, cols[:i]+cols[i+1:])
    return result

# det = determinant(0, [0, 1, 2, 3, 4, 5, 6, 7, 8])

result = inverse(mem)

print '[*] Determinant Calculated'
tmp_state.add_constraints(claripy.Or(result = 1))

print hex(tmp_state.se.any_str(vec))
