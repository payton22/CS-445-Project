#!/usr/bin/python3

from scapy.all import *

class DefenseModel:
    packet_dictionary = {}

    # Check to see if the packet type contains the right data
    # Avoids irrelevant packets, such as ICMP and ARP packets
    def check_packet_type(self, packet):

        print('check packet:')
        print(packet.show())
        print('next step')
        # Returns None if no payload data
        #if packet[Raw] is not None:
         #   entire_payload = packet.get(Raw)
        #else:
         #   entire_payload = None

        if Raw in packet:
            print('Raw is in packet.')
            return True
        else:
            print('Raw is not in packet.')
            return False

        
        print('got here.')
        # If it contains payload data, return True
        # otherise, return False
       # if entire_payload is not None:
        
       # return True
       # else:
        #    return False

    # Get the original payload data from a packet and hash it
    def extract_and_hash_packet(self, packet):
        # Get human readable data
        entire_payload = packet[Raw].load.decode('utf-8')
        # Split by |
        payload_list = entire_payload.split('|')
        # Read from the first element of the list (contains orig. payload data)
        data_only = payload_list[0]
        key_to_compare = hash(data_only)
        
        return key_to_compare, entire_payload

    def packet_comparison_algorithm(self, key_to_compare, entire_payload):
        
        print('In packet comparison algorithm')
        print('Examining packet:', entire_payload)
        payload_list = entire_payload.split('|')

        orig_src = self.find_orig_src(payload_list)
        if self.packet_dictionary.get(key_to_compare) is not None:
            print('Key is not None')
            stored_payload = self.packet_dictionary[key_to_compare]
            stored_payload_list = stored_payload.split('|')
            stored_orig_src = self.find_orig_src(stored_payload_list)
            if orig_src != stored_orig_src:
                print('Packet is flagged as duplicate.')
            else:
                print('Duplicate packet, but it came from the same source.')
        else:
            print('Adding to dictionary')
            self.packet_dictionary[key_to_compare] = entire_payload
            print('I\'ve never seen this packet before. I will add it to the dictionary')


    def find_orig_src(self, payload_list):
        print('paylooad list:', payload_list)
        for value in payload_list:
            if 'ORIG_SRC=' in value:
                orig_src = value.partition('ORIG_SRC=')[2]
                print('has orig src')
                return orig_src
            
        print('Returning None')
        return None


    def print_contents_of_packet_dictionary(self):
        print(self.packet_dictionary)



            
            
        
