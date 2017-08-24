import hashlib


base = "aaaaaaaaaaaaa"

for i in range(0xffff):

  s = hex(i)[2:]
  s = base + s.rjust(8, '\x00')

  m = hashlib.sha1()
  m.update(s)
  sha1val = m.hexdigest()

  print sha1val

  if sha1val[:7] == "0000000":
    print s, sha1val
