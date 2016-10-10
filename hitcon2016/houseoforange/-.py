from pwn import *


RED = 1
GREEN = 2
YELLOW = 3
BLUE = 4
PURPLE = 5
CYAN = 6
WHITE = 7
ORANGR = 56746


def build(length_name, name, price, color):
	s.recvuntil("choice : ")
	s.sendline('1')
	s.recvuntil('name :')
	s.sendline(str(length_name))
	s.recvuntil('Name :')
	s.sendline(name)
	s.recvuntil('Orange:')
	s.sendline(str(price))
	s.recvuntil('Orange:')
	s.sendline(str(color))
	s.recvuntil('Finish')

def see():
	s.recvuntil("choice : ")
	s.sendline('2')
	log.info(s.recvuntil('+'))

def upgrade(length_name, name, price, color):
	s.recvuntil("choice : ")
	s.sendline('3')
	s.recvuntil('name :')
	s.sendline(str(length_name))
	s.recvuntil('Name :')
	s.sendline(name)
	s.recvuntil('Orange:')
	s.sendline(str(price))
	s.recvuntil('Orange:')
	s.sendline(str(color))
	s.recvuntil('Finish')

s = remote('52.68.192.99', 56746)

build(10,'a'*9,50000,RED)
see()

s.interactive()
s.close()
