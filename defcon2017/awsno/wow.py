#!/usr/bin/python

from pwn import *
from time import sleep

url = "awsno_cfeaa78b474521963ccfd450cd938ce9.quals.shallweplayaga.me"
port = 80
while True:
	r = remote(url, port)

	wanna = "trains"

	r.sendline('GET /' + wanna + ' HTTP/1.1')
	r.sendline('')
	l = r.read()

	if l.find("Connection refused") != -1:
		r.close()
		continue

	r.interactive()

	r.close()
