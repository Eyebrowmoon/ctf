from pwn import *
import json
import base64

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = process('./attackme')

api_key = "ac261681692e300a406552de038cc01df05ef108e21857beac6c1c3dce6498d4"

a = {
  'apikey' : api_key,
}

p = remote("sss.eatpwnnosleep.com", 18878)
p.send(json.dumps(a).encode())

script = ""

DEBUG = False

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info("Received:" + response)
  return response

def s(msg, enter = True):
  msg = msg + "\n" if enter else msg
  p.send(msg)
  if DEBUG:
    log.info("Sent: " + msg)

filename1 = "astparser.c"
filename2 = "valenv.h"

r("finish")
s(filename1)

with open(filename1, 'r') as f:
  code = f.read()

r("base64 :")
s(base64.b64encode(code))

r("finish")
s(filename2)

with open(filename2, 'r') as f:
  code = f.read()

r("base64 :")
s(base64.b64encode(code))

p.interactive()
p.close()
