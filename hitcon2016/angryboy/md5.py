#!/usr/bin/python

import hashlib

m = hashlib.md5()

#ip = "fe80::dacb:8aff:fe18:b2ba"
ip = "141:223:175:203"
key = "84cb29d734f89f1a143b08b177fc2b1c".decode("hex")

m.update(ip+key)

print m.digest().encode("hex")
