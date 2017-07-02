#!/usr/bin/python
from z3 import *
from struct import pack, unpack


A = [
    0x1380, 0x4E4, 0x2709, 0x2035, 0x25FA, 0x56DA, 0x103, 0x1531,
    0x0CAA, 0x1A61, 0x0E07, 0x20, 0x0E2, 0x123F, 0x0C0, 0x0DC7
]

R = [
    0x146FC26A, 0x2434019A, 0x16B2964E, 0x1DFCC164,
    0x10766B04, 0x1F67E99D, 0x13905802, 0x14A99DA3,
    0x2AE5CE6C, 0x4048AA7F, 0x33CF9B5F, 0x2C101662,
    0x2DF5FCE4, 0x4C26C74C, 0x2CD5980F, 0x2BA9DEDB,
]

xor_key = [
    0x90DF, 0x70BC, 0x0EF57, 0x5A96, 0x0CFEE, 0x5509, 0x80CE, 0x0D20,
    0x0E14F, 0x70E, 0x0A446, 0x2FC6, 0x0ECF0, 0x5355, 0x782B, 0x6457
]

def solve():
    B = []
    for i in xrange(16):
        B.append(Int(i))

    s = Solver()
    for i in B:
        s.add(And(i >= 0, i <= 0xFFFF))

    for i in xrange(4):
        for j in xrange(4):
            s.add(
                B[i + 0 * 4] * A[j + 0 * 4] +
                B[i + 1 * 4] * A[j + 1 * 4] +
                B[i + 2 * 4] * A[j + 2 * 4] +
                B[i + 3 * 4] * A[j + 3 * 4] == R[i * 4 + j]
            )
    r = []
    if s.check() == sat:
        r = []
        model = s.model()
        for i in xrange(16):
            r.append(model[B[i]].as_long())
    else:
        print 'Oops'

    return r

def ror(n, c, bits=64):
    mask = (1 << bits) - 1
    return ((n >> c) | (n << (bits - c))) & mask

def rol(n, c, bits=64):
    return ror(n, bits - c, bits)

def sub(n, c, bits=64):
    mask = (1 << bits) - 1
    return (n - c) & mask

def xor_passwd(passwd):
    l = [0] * 16
    for i in xrange(16):
        l[i] = passwd[i] ^ xor_key[i]
    return l

def decrypt_block(data):
    q0, q1 = data
    x0 = 0x0A728E203850A80E
    x1 = 0x1B8E2679CCAEF6B4
    for i in xrange(32):
        x0 = ror(x0 ^ x1, 3)
        q1 = ror(q1 ^ q0, 3)
        x1 = rol(sub(x1 ^ (31 - i), x0), 8)
        q0 = rol(sub(q0 ^ x0, q1), 8)
    return q0, q1

def decrypt(data):
    res = []
    for i in xrange(0, len(data), 2):
        res.extend(decrypt_block(data[i:i + 2]))
    return res

def decrypt_passwd(passwd):
    l = unpack('>4Q', pack('>16H', *passwd))
    l = decrypt(l)
    l = unpack('>16H', pack('>4Q', *l))
    return l

passwd = solve()
passwd = decrypt_passwd(passwd)
passwd = xor_passwd(passwd)
print(''.join(map(chr, passwd)))
