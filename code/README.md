# Covert Storage Channel that Exploits Protocol Field Manipulation Using Root Delay Field in NTP

This project implements a covert storage channel by manipulating the Root Delay field in NTP messages to encode and transmit hidden information. The Root Delay field indicates the delay between the NTP server and the master clock. This implementation ensures covert communication while minimizing the risk of detection by avoiding noticeable alterations.

## Project Overview

- The covert storage channel utilizes the Root Delay field in NTP packets to transmit hidden binary messages. The project involves two primary functions:
  - *Send:* Encodes and transmits binary messages by manipulating the Root Delay field values.
  - *Receive:* Captures NTP packets and decodes the hidden messages from the Root Delay field.

- The implementation is built upon the CovertChannelBase class and utilizes Scapy for packet manipulation and sniffing.

## Methodology

### Encryption and Encoding

- *Message Preparation:*
  - Generates a random binary message of 128 bits.
  - Splits the message into 4-bit chunks for processing.

- *Encryption Process:*
  - *Step 1: XOR Key Generation*
    - For each 4-bit chunk, a random 4-bit XOR key is dynamically generated.
    - This XOR key is used to add a layer of randomness to the encryption process and ensures dynamic encryption for each packet.
  
  - *Step 2: Differential Encoding*
    - The XORed 4-bit value is further processed by keeping the first bit as is.
    - For the subsequent bits, each bit is compared with the previous one:
      - If the current bit is the same as the previous bit, write 1.
      - If the current bit is different, write 0.
    - This step creates a new 4-bit value that conceals the original data more effectively.

  - *Step 3: Mapping to 12 Bits Using encrypt Function*
    - The 4-bit value is passed to the custom encrypt function, which maps it to a 12-bit value based on the following formula:
      
      
      encrypted_value[i] = ((i + key + last_encrypted_value + current_bit) * i) % 8
      

      - i is the position of the bit in the sequence. i is starting from 1 not from 0. This is needed to ensure that we are not getting same '000' bit sequence for our first data bit.
      - key is the encryption key. This key is given to our functions send and receive as parameter.
      - last_encrypted_value is the value from the previous encryption cycle.
      - The dependency of the formula on the index value i and last_encrypted_value ensures that each bit contributes uniquely to the encrypted value, further increasing randomness.
  - *Final Packet Construction*
    - The least significant 16 bits of the Root Delay field are populated as follows:
      - The first 4 bits contain the XOR key.
      - The next 12 bits contain the result of the encrypt function.

### Decoding and Decryption

- *Packet Capture:*
  - The receiver captures incoming NTP packets and extracts the least significant 16 bits of the Root Delay field.

- *Decryption Process:*
  - *Step 1: XOR Key Recovery*
    - The first 4 bits of the field are extracted to retrieve the XOR key.

  - *Step 2: Brute Force Verification*
    - In last 12 bit for each 3 bit chunks, the receiver uses a brute force approach to determine whether each 3 bit chunk corresponds to a 0 or 1.

  - *Step 3: Differential Decoding*
    - The 4-bit differential encoded value is converted back to the differential decoded value:
      - Start with the first bit as is.
      - For each subsequent bit:
        - If the current bit is 1, the next decoded bit is the same as the previous one.
        - If the current bit is 0, the next decoded bit is the opposite of the previous one.

  - *Step 4: XOR Decryption*
    - The recovered XOR key is applied to the differential decoded value to reconstruct the original 4-bit message.

  - *Step 5: Message Reconstruction*
    - Each 8-bit chunks are converted to an ASCII character with the help of convert_eight_bits_to_character function.
    - The process continues until the stop character '.' is detected.

### Stop Condition

- The message ends with a stop character '.' represented by the binary sequence '00101110'.
- Sniffing stops once this sequence is detected.

## Covert Channel Capacity

To calculate the covert channel capacity:

- *Generate a Binary Message:*
  - Create a binary message that is 16 characters (128 bits) long.

- *Measure Time:*
  - Start the timer before sending the first packet.
  - Stop the timer after sending the last packet.
  - Record the total time in seconds.

- *Calculate Capacity:*
  - Divide 128 (message length in bits) by the recorded time in seconds.
  - Capacity (in bits per second) = 128 / time_in_seconds

### Achieved Covert Channel Capacity

- Time taken to send 128 bits: 0.7921831607818604 seconds
- Capacity = 128 / 0.7921831607818604 = 161.57879432032857 bits per second