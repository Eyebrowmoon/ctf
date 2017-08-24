from pwn import *
import json
import base64

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = process('./attackme')

api_key = 'ac261681692e300a406552de038cc01df05ef108e21857beac6c1c3dce6498d4'

a = {
  'apikey' : api_key,
}

script = ""

DEBUG = True

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

with open('libfilesys.so', 'r') as f:
  orig = f.read()

with open('libfilesys_patched3', 'r') as f:
  txt = f.read()

assert (sum(map(lambda x, y: x != y, orig, txt)) < 120)

p = remote("libfilesys.eatpwnnosleep.com", 10000)

r("api_key:")
s(api_key)

r("base64 :")
s(base64.b64encode(txt))


p.interactive()
p.close()
