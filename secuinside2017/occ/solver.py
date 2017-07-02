import requests
import sys

from pwn import *

print sys.argv

if len(sys.argv) < 2:
  print("Plz give me a file")
  sys.exit(0)

with open(sys.argv[1], 'r') as f:
  code = f.read()

print(code)

r = requests.post('http://13.124.94.39/', data = {'code': code})

if r.text.find('compile error') != -1:
  print("Compile Error!!!!")
  sys.exit(0)

out = r.text[ r.text.find('Result : ') + len('Result : ') : ]

print out[:1024].encode('hex')
