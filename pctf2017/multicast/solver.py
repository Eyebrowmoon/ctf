#!/usr/bin/python

def gcd(a, b):
  while b:
    a, b = b, a % b
  return a

def egcd(a, b):
  if (a == 0):
      return (b, 0, 1)
  else:
      g, y, x = egcd(b % a, a)
      return (g, x - (b // a) * y, y)

# Modular multiplicative inverse
def modInv(a, m):
  g, x, y = egcd(a, m)
  if (g != 1):
      raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
  else:
      return x % m

a = []
b = []
c = []
N = []

numdata = 0

f = open("data.txt")

while True:
  line = f.readline()
  if not line:
    break

  a.append(int(line))
  b.append(int(f.readline()))
  c.append(int(f.readline()))
  N.append(int(f.readline()))

  numdata += 1

f.close()   

ainv = []
bainv = []
d = []

for i in xrange(numdata):
  ainv.append(modInv(a[i], N[i]))
  bainv.append (pow (b[i] * ainv[i], 5, N[i]))

  new = (c[i] * pow(ainv[i], 5, N[i])) % N[i]
  new = (new - bainv[i]) % N[i]

  d.append (new)

f = open("/home/ebmoon/RsaCtfTool/pctf2017/priv")
priv = f.read().strip()
f.close()

privkey = int(priv.encode("hex"), 16)

cipher = pow(1234567890, 5, N[0])
print pow(cipher, privkey, N[0])

plain = pow(c[0], privkey, N[0])
m = ((plain - b[0]) * ainv[0]) % N[0]

print hex(m)

"""
for i in xrange(0, 5):
  for j in xrange(i+1, 5):
    print hex(bainv[i] - bainv[j])
"""
