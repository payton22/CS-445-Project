#!/usr/bin/python3

from scapy.all import *

class DefenseModel:
    packet_dictionary = {}

    # Check to see if the packet type contains the right data
    # Avoids irrelevant packets, such as ICMP and ARP packets
    def check_packet_type(self, packet):

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

        orig_dst = self.find_orig_dst(payload_list)
        if self.packet_dictionary.get(key_to_compare) is not None:
            print('Key is not None')
            stored_payload = self.packet_dictionary[key_to_compare]
            stored_payload_list = stored_payload.split('|')
            stored_orig_dst = self.find_orig_dst(stored_payload_list)
            if orig_dst != stored_orig_dst:
                print('Packet is flagged as duplicate.')
                self.generate_alert(orig_dst, stored_orig_dst, entire_payload)
            else:
                print('Duplicate packet, but it came from the same dst.')
        else:
            print('Adding to dictionary')
            self.packet_dictionary[key_to_compare] = entire_payload
            print('I\'ve never seen this packet before. I will add it to the dictionary')


    def generate_alert(self, orig_dst, stored_orig_dst, entire_payload):
        f = open('alert.txt', 'a')
        f.write('\n--------------- Alert - Duplicate packet detected! ---------------')
        f.write('\nDestination 1: ')
        f.write(orig_dst)
        f.write('\nDestination 2: ')
        f.write(stored_orig_dst)
        f.write('\nPayload data: ')
        f.write(entire_payload)
        f.write('\n---------------             End of Alert           ---------------')
        f.write('\n')
        f.close()

    def find_orig_dst(self, payload_list):
        print('paylooad list:', payload_list)
        for value in payload_list:
            if 'ORIG_DST=' in value:
                orig_dst = value.partition('ORIG_DST=')[2]
                print('has orig src')
                return orig_dst
            
        print('Returning None')
        return None


    def print_contents_of_packet_dictionary(self):
        print(self.packet_dictionary)



            
            
        
