import hashlib

filename = 'sample4'
f = open(filename)
content = f.read()
f.close()

e = 0x10001
N = """
    00:b9:a5:92:e9:75:f1:4f:69:c6:33:df:f1:77:94:
    b9:b8:15:96:99:e4:84:d8:1c:d8:b2:37:cf:f3:12:
    28:fe:e2:0a:d3:25:9b:2a:0e:ab:26:b9:7c:60:19:
    65:13:e1:bb:a5:a8:c4:82:6f:8d:56:2a:ca:32:ca:
    a4:f9:db:52:0b:4c:37:bc:39:86:e9:aa:65:83:36:
    62:0b:e0:ec:37:61:d7:c4:19:7d:dd:1f:82:c9:df:
    ab:dd:38:2c:1b:6b:00:ae:87:12:2b:1a:b4:81:07:
    59:9c:7e:a9:19:aa:23:95:c3:53:85:79:12:99:8d:
    78:fa:7c:cf:d3:54:00:e5:cf:17:34:d9:d0:b6:45:
    8a:91:a3:2c:ea:27:6f:1a:07:3e:3b:ed:f2:3c:87:
    01:63:78:72:40:09:9a:38:67:e0:94:6a:a6:f4:ff:
    11:04:c7:74:7a:a5:97:18:88:d3:2e:05:4c:83:d4:
    56:41:61:79:58:35:e9:75:bc:1b:e9:8b:9b:2a:63:
    b1:2a:21:d6:3e:09:35:2f:ef:88:03:75:b8:d5:06:
    bb:6c:08:39:be:ca:4d:dd:b8:14:f4:a5:e4:3a:b2:
    4b:e5:ae:64:8d:7f:f3:d6:ed:c6:4b:69:3b:59:93:
    54:1f:75:c2:b8:85:e1:e7:76:e3:4f:3f:3e:76:41:
    c3:9f
"""
N = N.replace(":", "").replace("\n", "").replace(" ", "")
N = int(N, 16)

sigsize = 0x100

main_content = content[:-sigsize]
signature = content[-sigsize:]

m = hashlib.sha256(main_content).hexdigest()

hash_file = int(m, 16)
sig_int = int(signature.encode("hex"), 16)

f = open(filename + "_dgst", "w")
f.write(main_content)
f.close()

f = open(filename + "_sig", "w")
f.write(signature)
f.close()

print hash_file
print "\n"

print pow(hash_file, e, N)
print "\n"

print sig_int
print "\n"

print pow(sig_int, e, N)
print "\n"

