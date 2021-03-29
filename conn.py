#!/usr/bin/env python3

import sys
from scapy.all import *
conf.verb=0

source = sys.argv[1]
target = sys.argv[2]

p1=IP(dst=target,src=source)/TCP(dport=port,sport=50001,flags='S')
r1=sr1(p1)

print("this packet was sent: ")
p1.show()

print(" this was the reply: ")
r1.show()

sys.exit(0)
