from CovertChannelBase import CovertChannelBase
import scapy.all as scapy
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def encrypt(self, message, key):
        encrypted_message = ""
        last_encrypted_value = 0
        for i in range(1, len(message)+1):
            current_message = ((i+key+last_encrypted_value+int(message[i-1]))*i)%8
            encrypted_message += format(current_message, '03b')
            last_encrypted_value = current_message
        return encrypted_message


    def send(self, key, log_file_name):
        """
        Sends covert messages by encoding data in NTP packet delay fields:
        1. Generates random binary message
        2. Processes it in 4-bit chunks
        3. Applies XOR and custom encryption
        4. Embeds in NTP packet delay field
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)
        
        for i in range(0, len(binary_message), 4):
            # Process message in chunks of 4 bits
            current_partition = binary_message[i:i+4]
            current_partition = int(current_partition, 2)
            
            # Generate XOR key and apply
            xor_key = self.generate_random_binary_message(min_length=10, max_length=10)[50:54]
            xor_int = int(xor_key, 2)
            xored_value = current_partition ^ xor_int
            xored_value = format(xored_value, '04b')
            
            # Convert to differential encoding
            converted_value = xored_value[0]
            for j in range(1, 4):
                converted_value += '1' if xored_value[j] == xored_value[j-1] else '0'
                
            # Apply further encryption
            encrypted_value = self.encrypt(converted_value, key)
            
            # Construct final message
            covert_data = xor_key + encrypted_value
            delay_value = int(covert_data, 2)
            
            # Create and send packet
            try:
                packet = scapy.IP(dst="receiver")/scapy.UDP()/scapy.NTP(delay=delay_value)
                if i == 0:
                    t_start = time.time()
                CovertChannelBase.send(self, packet)
                if i == len(binary_message)-4:
                    t_end = time.time()
                    print(f"Time taken: {t_end - t_start}")
                    print(f"Channel Capacity: {128/(t_end - t_start)}")
            except Exception as e:
                print(f"Error sending packet: {e}")


            
    def receive(self, key, log_file_name):
        """
        Receives and decrypts covert messages from NTP packet delay fields:
        1. Captures NTP packets
        2. Extracts and processes delay field values
        3. Reverses encryption and encoding steps
        4. Reconstructs original message
        """
        received_message = ""
        stop_sniffing = False
        def process_packet(packet):
            nonlocal received_message
            nonlocal stop_sniffing
            if scapy.NTP in packet:
                try:
                    # Extract delay value and convert to binary
                    delay_value = packet[scapy.NTP].delay
                    binary_value = format(int(delay_value), '016b')
                    
                    # Split into XOR key and encrypted data
                    xor_key = binary_value[:4]
                    encrypted_data = binary_value[4:]
                    
                    # Decrypt the data
                    decrypted = ""
                    last_value = 0
                    for i in range(0, len(encrypted_data), 3):
                        chunk = encrypted_data[i:i+3]
                        val = int(chunk, 2)
                        # Reverse the encryption formula
                        for possible_bit in ['0', '1']:
                            test_val = ((len(decrypted)+1+key+last_value+int(possible_bit)) * 
                                        (len(decrypted)+1)) % 8
                            if test_val == val:
                                decrypted += possible_bit
                                last_value = val
                                break
                    
                    # Convert from differential encoding
                    converted = decrypted[0]
                    prev_bit = decrypted[0]
                    for i in range(1, 4):
                        if decrypted[i] == '0':
                            current_bit = '1' if prev_bit == '0' else '0'
                        else:
                            current_bit = prev_bit
                        converted += current_bit
                        prev_bit = current_bit
                    
                    # Apply XOR to get original bits
                    xor_int = int(xor_key, 2)
                    final_value = int(converted, 2) ^ xor_int
                    received_message += format(final_value, '04b')

                    # Check for stop character
                    if received_message.endswith("00101110"):
                        stop_sniffing = True
                    
                except Exception as e:
                    print(f"Error processing packet: {e}")
        
        # Sniff NTP packets
        scapy.sniff(filter="host sender and port ntp", prn=process_packet, stop_filter= lambda x: stop_sniffing)
        
        decoded_message = ""
        for i in range(0, len(received_message), 8):
            eight_bits = received_message[i:i+8]
            character = self.convert_eight_bits_to_character(eight_bits)
            decoded_message += character
        
        # Log the decoded message instead of binary
        self.log_message(decoded_message, log_file_name)
