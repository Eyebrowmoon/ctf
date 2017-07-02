import string
import subprocess

from pwn import *

CMD = "./alchemy_dist/f3d21b65d46ac6f912563079c78b91528817fb4918a81f9c54a49552a48e89e6"

def test(s, fname):
  """Execute the command CMD with "s" as input, return the exit code."""
  child = subprocess.Popen(fname, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  child.communicate(s)

  return child.returncode

def brute(fname):
  s = ""
  prev_ret = test(s + "\x00", fname)

  while True:
    for c in string.printable:
      ret = test(s + c + "\x00", fname)

      if ret != prev_ret:
        print c
        s += c
        prev_ret = ret
        break
      
def do(fname):
  print "solving for {}".format(fname)

  sol = brute(fname)

do(CMD)

"""
for c in string.printable:
  ret = test(c + "\x00", CMD)

"""
