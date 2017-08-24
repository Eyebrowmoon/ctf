import base64
from pwn import *

f = open ("auto.c")
txt = f.read()
f.close()

payload = base64.b64encode(txt)

DEBUG = True

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info(response)
  return response

def s(msg, enter = True):
  msg = msg + "\n" if enter else msg
  p.send(msg)
  if DEBUG:
    log.info("Sent: " + msg)

p = remote('dfa.eatpwnnosleep.com', 9999)

r("finish")
s("auto.c")

r("base64 : ")
s(payload)

p.interactive()
p.close()
