
class DefenseModel:
    packet_dictionary = {}

    # Check to see if the packet type contains the right data
    # Avoids irrelevant packets, such as ICMP and ARP packets
    def check_packet_type(self, packet):

        print('check packet:', packet)
        # Returns None if no payload data
        entire_payload = packet.get(Raw)

        # If it contains payload data, return True
        # otherise, return False
        if entire_payload is not None:
            return True
        else:
            return False

    # Get the original payload data from a packet and hash it
    def extract_and_hash_packet(self, packet):
        # Get human readable data
        entire_payload = entire_payload.load.decode('utf-8')
        # Split by |
        payload_list = entire_payload.split('|')
        # Read from the first element of the list (contains orig. payload data)
        data_only = payload_list[0]
        key_to_compare = hash(data_only)

        return key_to_compare, entire_payload

    def packet_comparison_algorithm(self, key_to_compare, entire_payload):
        payload_list = entire_payload.split('|')

        orig_src = self.find_orig_src(payload_list)

        if packet_dictionary.get(key_to_compare) is not None:
            stored_payload = packet_dictionary[key_to_compare]
            stored_payload_list = stored_payload.split('|')
            stored_orig_src = self.find_orig.src(stored_payload_list)
            if orig_src != stored_orig_src:
                print('Packet is flagged as duplicate.')
            else:
                print('Duplicate packet, but it came from the same source.')
        else:
            packet_dictionary[key_to_compare] = entire_payload
            print('I\'ve never seen this packet before. I will add it to the dictionary')


    def find_orig_src(self, payload_list):
        for value in payload_list:
            if 'ORIG_SRC=' in value:
                orig_src = value.partition('ORIG_SRC=')[2]
                return orig_src
            else:
                return None


    def print_contents_of_packet_dictionary(self):
        print(self.packet_dictionary())



            
            
        
