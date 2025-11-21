import os
from Crypto.Cipher import AES 


def prf(key, input): 
    if len(key) != 16 or len(input) != 16: #key and input has to be 16 bytes for AES128 as learned in class
        print("Key and input must be 16 bytes long")
        return None
    
    cipher = AES.new(key, AES.MODE_ECB) #create AES cipher in ECB mode
    output = cipher.encrypt(input) #encrypt the input 
    return output

def pad(data): #pad data to 16 bytes
    required = 16 - len(data)
    if required > 0:
        data = data + (b'\x00' * required)
    return data[:16] #ensure data is exactly 16 bytes

def split_blocks(message, size): #block splitting function   
    blocks = []
    i = 0
    while i < len(message):
        chunk = message[i : i + size]
        blocks.append(chunk)
        i = i + size
    return blocks

def mac_compute(key, message, block_size=15): 
    blocks = split_blocks(message, block_size) #split message into block of size 15 bytes
    num_blocks = len(blocks)  # number of blocks
    tag_parts = []

    for i, block in enumerate(blocks): #for each block we need to compute a tag using Fk(ℓ||i||mi)
        prf_input = bytes([num_blocks, i]) + block 
        prf_input = pad(prf_input) 
        prf_output = prf(key, prf_input)  #apply prf
        tag_parts.append(prf_output)

    tag = b''.join(tag_parts) #combine the tags
    return tag

def mac_verify(key, message, tag): #If the computed tag matches the provided tag then autentication is successful
    expected = mac_compute(key, message)
    yes = expected == tag
    return yes

if __name__ == "__main__": #mix and match attack 
    key = os.urandom(16)

    print("---- CS549 MAC Demo ----") #Simple UI as requested in assignment description
    print("1. Compute MAC for a message")
    print("2. Run mix-and-match attack example")
    print("3. Exit")

    answer = input("Select an option (1-3): ") #gets user input 

    match answer:   #switch case
        case "1":
            message = input("Enter a message: ").encode() #get message 
            tag = mac_compute(key, message) #compute tag
            print("Tag:", tag.hex()) #print tag in hex

        case "2": #mix and match attack example
            message1 = b"CS549 homework is hard!"
            tag1 = mac_compute(key, message1)
            message2 = b"CS549 homework is easy!"
            tag2 = mac_compute(key, message2)

            message1_blocks = split_blocks(message1, 15)
            message2_blocks = split_blocks(message2, 15)

            forged_message = message1_blocks[0] + message2_blocks[1]
            first_block = tag1[:16]
            second_block = tag2[16:]
            forged_tag = first_block + second_block

            print("Forged Message:", forged_message)
            print("Forged Tag:", forged_tag.hex())
            print("Forgery successful?", mac_verify(key, forged_message, forged_tag))

        case _:
            print("Exited")







