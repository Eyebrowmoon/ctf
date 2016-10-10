#!/usr/bin/python
import sys
import ctypes
DWORD = ctypes.c_uint32
#Stack SS:[0012FF1C]=A8A3A8F5
#Stack SS:[0012FF20]=A5B82AB1


#Stack SS:[0012FF1C]=A8A3A8F5

ta = [1,2,3,4]
def numjob_4016d0(inp, inp_count, ta):
	output = []
	for i in range(0, inp_count, 2):
		si = inp[i]
		di = inp[i+1]
		a = 0x7cbf26c0
		for j in range(0x40):
			d = si / 32
			c = si * 16
			d = d^c
			c = a / pow(2, 11)
			c = c & 3
			d += si
			c = ta[c]
			c += a
			d ^= c
			#pdb.set_trace()
			di = DWORD(di - d).value
			d = di
			d /= pow(2,5)
			c = di
			c = DWORD(c * 16).value
			d ^= c
			a = DWORD(a + 0x160d0365).value
			c = a
			c = c & 3
			d = DWORD(d + di).value
			c = ta[c]
			c = DWORD(c + a).value
			d ^= c
			si = DWORD(si - d).value
			#print hex(si), hex(di)
		output.append([si, di])
	return output

#a = numjob_4016d0([0x11111,0x22222], 2, [1,2,3,4])
#pdb.set_trace()
def aa(a,b):
	xx=numjob_4016d0([a,b],2,[1,2,3,4])
	print hex(xx[0][0]),
	print hex(xx[0][1])

if len(sys.argv) != 3:
	aa(1, 2)
else:
	aa(int(sys.argv[1]), int(sys.argv[2]))
