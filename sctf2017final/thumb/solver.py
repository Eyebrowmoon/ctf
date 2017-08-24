from ctypes import *

arr_10938 = [0] * 0x271

arr_10938[0] = 0xc0ffee
for i in range(1, 0x270):
  prev = arr_109e8[i - 1]
  arr_10938[i] = c_int(0x6c078965) * (prev >> 30) ^ prev + i

arr_10938[0x270] = 624 # 112f8


