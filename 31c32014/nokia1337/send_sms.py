#!/usr/bin/env python

import struct
import sys

if len(sys.argv) != 4:
	print "Usage: ./send_sms.py <sendernr> <recvnr> <text>"
	sys.exit(1)

sys.stdout.write(struct.pack("<Bii161s", 0xFF, int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]))
