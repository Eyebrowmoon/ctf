import sys

target = sys.argv[1]

f = open(target)
binary = f.read()
f.close()

hexstr = ''
for c in binary:
  hexstr += c.encode("hex") + " "

print hexstr
