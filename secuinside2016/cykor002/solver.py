import angr
import os
import base64
import datetime
import time
import simuvex
from pwn import *

BINARY = 'a.out'

DEBUG = True

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    print "[*] " + response
  return response

def generate_exploit ():
  BIN = BINARY

  project = angr.Project(BIN)
  elf = ELF(BIN)

  entry_point = elf.entry
  target_addr = 0x8048d03
  fail_addr = 0x8048d0d
  buf_addr = 0x804a024

  # Run angr
  buf = angr.claripy.BVS("buf", 0x19 * 32)

  start_state = project.factory.blank_state(addr = entry_point)
  start_state.options.discard("LAZY_SOLVES")
  start_state.se._solver.timeout = 10000
  start_state.memory.store(buf_addr, buf)
   
  pg = project.factory.path_group(start_state, immutable = False)
  pg.explore(find = target_addr, avoid = fail_addr)

  payload = pg.found[0].state.se.any_str(buf)
  
  if DEBUG:
    log.info("Payload: %s" % payload.encode("hex"))

  return payload

def main():
  payload = generate_exploit ()

  if not DEBUG:
    os.system("./bins/%s" % BINARY)

if __name__ == '__main__':
  sys.exit(main())

