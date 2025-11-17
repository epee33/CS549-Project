import os
from Crypto.Cipher import AES 


def prf(key, input): 
    if len(key) != 16 or len(input) != 16: #key and input has to be 16 bytes for AES-128
        raise ValueError("Key and input must be 16 bytes long")
    
    cipher = AES.new(key, AES.MODE_ECB) #create AES cipher in ECB mode
    output = cipher.encrypt(input) #encrypt the input 
    return output

def pad_to_16(data): #pad data to 16 bytes
    needed = 16 - len(data) 
    if needed > 0: 
        data = data + (b'\x00' * needed)
    return data

def split_blocks(message, size): #very basic block splitting function   
    blocks = []
    start = 0
    while start < len(message):
        blocks.append(message[start:start+size])
        start += size
    return blocks

def mac_compute(key, message, block_size=15): 
    blocks = split_blocks(message, block_size) #split message into block of size 15 bytes
    num_blocks = len(blocks)  # number of blocks
    tag_parts = []

    for i, block in enumerate(blocks): #for each block we need to compute a tag using Fk(ℓ||i||mi)
        prf_input = bytes([num_blocks, i]) + block 
        prf_input = pad_to_16(prf_input) 
        prf_output = prf(key, prf_input)  #apply prf
        tag_parts.append(prf_output)

    tag = b''.join(tag_parts) #combine the tags
    return tag

def mac_verify(key, message, tag): #If the computed tag matches the provided tag then autentication is successful
    expected = mac_compute(key, message)
    return expected == tag


