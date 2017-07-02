import sys
import base64

filename = sys.argv[1]
f = open(filename)
key_arr = f.readlines()[1: -1]
f.close()

key = ''
for line in key_arr:
  key += line.strip()

print base64.b64decode(key)
