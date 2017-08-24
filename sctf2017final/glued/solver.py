from Crypto.Util import number

def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, x, y = egcd(b % a, a)
    return (g, y - (b // a) * x, x)

def mulinv(b, n):
  g, x, _ = egcd(b, n)
  if g == 1:
    return x % n

with open('log') as f:
  text = f.read().split("\n")

m = number.bytes_to_long('\x01' * (512 / 8))

N = int(text[0].split(" ")[-1], 16)
dlen = int(text[1].split(" ")[-1])
enc = int(text[2].split(" ")[-1], 16)
sign = int(text[3].split(" ")[-1], 16)
e = 257
k = 158

att = [0] * 128

dl = []

for i in range(8, 119):
  att[i] = int(text[i - 4].split(" ")[-1], 16)

res = 16883232848144752354869958129718294668601166599408523598101987032913299317702146934957636687478384206375343323017627835479911047483498214345790348093013029632028091576676405439641351172578329391162691824733271227530821225407237423382008330594548399038004710057166932295637164885205964462

mx = pow(m, res, N)
exp = 1 << 72

"""
lhs = (sign * pow(mx ^ 0xff, exp, N)) % N
rhs = (att[118] * pow(mx, exp, N)) % N

if lhs == rhs:
  print 'good'
"""

res <<= 72

s = ()

print prime_sum

st = 0
en = 1 << 516
mid = (st + en) / 2

"""
for i in range(520):
  p1 = prime_sum / 2 + st
  q1 = prime_sum - p1

  p2 = prime_sum / 2 + en
  q2 = prime_sum - p2

  p3 = prime_sum / 2 + mid
  q3 = prime_sum - p3

  d1, d2, d3 = (N - p1 * q1), (N - p2 * q2), (N - p3 * q3)

  if d1 * d3 < 0:
    st, en = st, mid
  else:
    st, en = mid, en

  mid = (st + en) / 2

p = prime_sum / 2 + mid
q = prime_sum - p

print p, q

print abs(N - p * q)
"""


dd = (1 + k * (N + 1)) // e

print res
print dd
