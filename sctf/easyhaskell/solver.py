from pwn import *
import os

context.log_level = 'error'

filename = "SCTF{D0_U_KNoW_fUnc10N4L_L4n9U4g3="
flag = "=ze=/<fQCGSNVzfDnlk$&?N3oxQp)K/CVzpznK?NeYPx0sz5"
flaglen = 46

print len(flag)

pchr = ";<>?`| \"%&'()*+/"

firstset = "0"

for first in firstset:
  for i in range(0x30, 0x7f):
    c1 = chr(i)

    if c1 in pchr:
      continue

    filename_ = filename + first + c1
    
    os.system("cp easyhaskell %s" % filename_)
    p = process(filename_)
    os.system("rm %s" % filename_)

    res = p.recvall()[1:-2]

    if flag[:flaglen] in res:
      print filename_, res

    p.close()
