from pwn import *
import json
import time
import zlib
import struct

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = process('./attackme')

api_key = "ac261681692e300a406552de038cc01df05ef108e21857beac6c1c3dce6498d4"

with open('solve.cpp', 'r') as f:
  code = f.read()

a = {
  'apikey' : api_key,
  'probid' : 'longest-substr', 
  'sourcetype' : 'cpp',
  'code' : code,
}

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

p = remote("longest-substr.eatpwnnosleep.com", 9000)
p.send(json.dumps(a).encode())

p.interactive()
p.close()
