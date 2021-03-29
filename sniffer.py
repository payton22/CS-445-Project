#!/usr/bin/python3
# Python file for the packet sniffer
# Incorporates scapy to capture packets in the network and 
# send them to the attacker

from scapy.all import *

def packet_sniffer():
    print('Calling packet sniffer function.')
    pkt = sniff(filter='tcp', count=1, iface='eth1', prn=lambda x:x.summary())
    

if __name__=='__main__':
    packet_sniffer()
    
