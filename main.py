import os
from Crypto.Cipher import AES 


def prf(key, input): 
    if len(key) != 16 or len(input) != 16: #key and input has to be 16 bytes for AES-128
        raise ValueError("Key and input must be 16 bytes long")
    
    cipher = AES.new(key, AES.MODE_ECB) #create AES cipher in ECB mode
    output = cipher.encrypt(input) #encrypt the input 
    return output