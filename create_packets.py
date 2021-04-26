#!/usr/bin/python3
# Python file for the packet sniffer
# Incorporates scapy to capture packets in the network and 
# send them to the attacker

from scapy.all import *
from copy import deepcopy
from random import randint
import os
import my_ips
import router
from time import sleep

#---
def send_to_router(packet):
    true_src = packet[IP].src
    true_dst = packet[IP].dst
    true_dport = packet[TCP].dport
    true_load = packet[Raw].load

    load_append = ('|ORIG_DST=' + true_dst).encode("utf-8")

    new_packet = IP(dst=my_ips.router_ip)/TCP(dport=true_dport)/Raw(load=true_load + load_append)

    print('Sending packet to router')
    r1 = send(new_packet, iface='eth1')


# Simulate external host that sends randomized packets
def build_packet(external_host_ip, external_ip):
    RANDOMIZED_WORDS = ['This', 'packet', 'sentence', 'password', 'username', 
            'advertisement', 'confidential', 'urgent', 'email', 'facebook', 'twitter',
            'linkedin', 'important', 'details', 'about', 'this', 'warranty', 
            'family', 'colleague', 'low', 'priority', 'social', 'security', 'number',
            'is', '555-55-5555', 'credit', 'card', 'number', 'is', '4444-4444-4444-4444', 
            'bank', 'account', 'number', 'is', '1234567', 'routing', 'number', 'is', 
            '2222222']

    # Generate a payload with a string of 10 randomized characters
    MAX = 10
    payload_string = ''
    # Loop through 10 times to randomly select the 10 words
    for i in range(0, MAX):
        payload_string += RANDOMIZED_WORDS[randint(0, len(RANDOMIZED_WORDS) - 1)]
        if i != MAX - 1:
            payload_string += ' '

    
    attacker_packet = IP(dst=my_ips.router_ip)/TCP(dport=80)/Raw(load=payload_string)

    
    # Append the original victim destination at end of payload

    packet = IP(src=external_host_ip, dst=external_ip)/TCP(dport=80)/Raw(load=payload_string)
    send_to_router(packet)

def send_packet(packet):
    print('Sending external packet')
    r1 = send(packet, iface='eth1')
    


while True:
    build_packet(my_ips.victim_ip, my_ips.external_host_ip)
    sleep(5)
