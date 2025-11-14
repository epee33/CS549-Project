import os
from Crypto.Cipher import AES 


def prf(key, input): 
    if len(key) != 16 or len(input) != 16: #key and input has to be 16 bytes for AES-128
        raise ValueError("Key and input must be 16 bytes long")
    
    cipher = AES.new(key, AES.MODE_ECB) #create AES cipher in ECB mode
    output = cipher.encrypt(input) #encrypt the input 
    return output

#Now we need to do the Mac Computation
def pad_to_16(data):
    while len(data) < 16: #add zeros until length is 16
        data += b'\x00'
    return data[:16] #return first 16 bytes

def mac_compute(key, message, block_size=15): #split message into 15 byte blocks
    blocks = []
    for i in range(0, len(message), block_size):
        block = message[i:i+block_size]
        blocks.append(block)

    num_blocks = len(blocks)  # number of blocks
    tag_parts = []

    for i, block in enumerate(blocks): #for each block we need to compute a tag using Fk(ℓ||i||mi)
        prf_input = bytes([num_blocks, i]) + block
        prf_input = pad_to_16(prf_input) #pad
        prf_output = prf(key, prf_input)  #apply prf
        tag_parts.append(prf_output)

    tag = b''.join(tag_parts) #combine the tags
    return tag, num_blocks

def mac_verify(key, message, tag, block_size=15):
    computed_tag, ell = mac_compute(key, message, block_size)
    return computed_tag == tag