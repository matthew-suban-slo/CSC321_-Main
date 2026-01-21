#!/usr/bin/env python3
"""
BMP File Encryption using AES ECB and CBC modes
Encrypts cp-logo.bmp and mustang.bmp using both ECB and CBC encryption modes.
"""

import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii
import numpy as np
from numpy import ndarray
import matplotlib.pyplot as plt
from PIL import Image

# Block size for AES
BLOCK_SIZE = 16

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """PKCS#7 padding implementation"""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """PKCS#7 unpadding implementation"""
    if len(padded) == 0 or len(padded) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return padded[:-pad_len]

def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES ECB encryption with manual block-by-block processing"""
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = b''
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext += cipher.encrypt(block)
    return ciphertext

def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES ECB decryption with manual block-by-block processing"""
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    plaintext = b''
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext += cipher.decrypt(block)
    return pkcs7_unpad(plaintext, BLOCK_SIZE)

def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """AES CBC encryption with manual block-by-block processing"""
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = b''
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        # XOR with previous ciphertext (or IV for the first block)
        xored = bytes(a ^ b for a, b in zip(block, prev))
        cipher = AES.new(key, AES.MODE_ECB)
        enc = cipher.encrypt(xored)
        ciphertext += enc
        prev = enc
    return ciphertext

def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """AES CBC decryption with manual block-by-block processing"""
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    plaintext_padded = b''
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext_padded += plain_block
        prev = block
    return pkcs7_unpad(plaintext_padded, BLOCK_SIZE)

def encrypt_bmp_files():
    """Encrypt both BMP files using ECB and CBC modes"""
    
    # Generate random key and IV
    key = get_random_bytes(16)  # 128-bit key
    iv = get_random_bytes(16)    # 128-bit IV
    
    print("=== BMP File Encryption Demo ===")
    print(f"Key (hex): {key.hex()}")
    print(f"IV (hex): {iv.hex()}")
    print()
    
    # List of BMP files to encrypt
    bmp_files = ['cp-logo.bmp', 'mustang.bmp']
    
    for bmp_file in bmp_files:
        if not os.path.exists(bmp_file):
            print(f"Warning: {bmp_file} not found, skipping...")
            continue
            
        print(f"Processing {bmp_file}...")
        
        # Read the BMP file
        with open(bmp_file, 'rb') as f:
            file_data = f.read()
        
        print(f"  Original file size: {len(file_data)} bytes")
        
        # ECB Encryption
        print("  Encrypting with ECB...")
        ecb_encrypted = aes_ecb_encrypt(key, file_data)
        ecb_filename = f"{bmp_file.split('.')[0]}_ecb_encrypted.bmp"
        with open(ecb_filename, 'wb') as f:
            f.write(ecb_encrypted)
        print(f"    ECB encrypted file saved as: {ecb_filename}")
        print(f"    ECB encrypted size: {len(ecb_encrypted)} bytes")
        
        # Test ECB decryption
        ecb_decrypted = aes_ecb_decrypt(key, ecb_encrypted)
        print(f"    ECB decryption test: {'PASS' if ecb_decrypted == file_data else 'FAIL'}")
        
        # CBC Encryption
        print("  Encrypting with CBC...")
        cbc_encrypted = aes_cbc_encrypt(key, file_data, iv)
        cbc_filename = f"{bmp_file.split('.')[0]}_cbc_encrypted.bmp"
        with open(cbc_filename, 'wb') as f:
            f.write(cbc_encrypted)
        print(f"    CBC encrypted file saved as: {cbc_filename}")
        print(f"    CBC encrypted size: {len(cbc_encrypted)} bytes")
        
        # Test CBC decryption
        cbc_decrypted = aes_cbc_decrypt(key, cbc_encrypted, iv)
        print(f"    CBC decryption test: {'PASS' if cbc_decrypted == file_data else 'FAIL'}")
        
        print()

def demonstrate_ecb_vs_cbc():
    """Demonstrate the difference between ECB and CBC modes"""
    print("=== ECB vs CBC Mode Demonstration ===")
    
    # Create a simple test pattern to show ECB's weakness
    test_pattern = b'AAAAAAAAAAAAAAAA' * 4  # 64 bytes of repeated pattern
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    print("Test pattern: 64 bytes of repeated 'A' characters")
    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print()
    
    # ECB encryption
    ecb_encrypted = aes_ecb_encrypt(key, test_pattern)
    print("ECB encrypted (hex):")
    print(ecb_encrypted.hex())
    print("Notice: repeated patterns in plaintext create repeated patterns in ciphertext")
    print()
    
    # CBC encryption
    cbc_encrypted = aes_cbc_encrypt(key, test_pattern, iv)
    print("CBC encrypted (hex):")
    print(cbc_encrypted.hex())
    print("Notice: CBC mode breaks up repeated patterns due to chaining")
    print()
    
    # Verify both can be decrypted correctly
    ecb_decrypted = aes_ecb_decrypt(key, ecb_encrypted)
    cbc_decrypted = aes_cbc_decrypt(key, cbc_encrypted, iv)
    
    print(f"ECB decryption test: {'PASS' if ecb_decrypted == test_pattern else 'FAIL'}")
    print(f"CBC decryption test: {'PASS' if cbc_decrypted == test_pattern else 'FAIL'}")

def show_img(image: ndarray, file_name):
    plt.title(file_name)
    plt.imshow(image)
    plt.axis("off")
    plt.show()

def display_encrypted_image(encrypted_filename: str, original_shape: tuple, display_label: str):
    """Display an encrypted image file by reading it as raw bytes and reshaping"""
    if not os.path.exists(encrypted_filename):
        return
    
    with open(encrypted_filename, 'rb') as f:
        encrypted_data = f.read()
    
    # Convert to numpy array and reshape to approximate image dimensions
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    total_bytes = len(encrypted_array)
    
    if len(original_shape) == 3:
        # RGB image
        pixels = total_bytes // 3
        aspect_ratio = original_shape[1] / original_shape[0]
        height = int(np.sqrt(pixels / aspect_ratio))
        width = int(height * aspect_ratio)
        # Adjust to fit the data
        if height * width * 3 > total_bytes:
            width = total_bytes // (height * 3)
        img_array = encrypted_array[:height*width*3].reshape((height, width, 3))
    else:
        # Grayscale image
        pixels = total_bytes
        aspect_ratio = original_shape[1] / original_shape[0]
        height = int(np.sqrt(pixels / aspect_ratio))
        width = int(height * aspect_ratio)
        if height * width > total_bytes:
            width = total_bytes // height
        img_array = encrypted_array[:height*width].reshape((height, width))
    
    show_img(img_array, f"{display_label}: {encrypted_filename}")

if __name__ == "__main__":
    # Encrypt the BMP files
    encrypt_bmp_files()
    
    # Demonstrate ECB vs CBC differences
    demonstrate_ecb_vs_cbc()
    
    print("Encryption complete!")
    
    # Display the original image and encrypted variants in separate windows
    bmp_file = 'cp-logo.bmp'
    if os.path.exists(bmp_file):
        # Display original image
        img = Image.open(bmp_file)
        img_array = np.array(img)
        original_shape = img_array.shape
        show_img(img_array, f"Original: {bmp_file}")
        
        # Display ECB and CBC encrypted images
        base_name = bmp_file.split('.')[0]
        display_encrypted_image(f"{base_name}_ecb_encrypted.bmp", original_shape, "ECB Encrypted")
        display_encrypted_image(f"{base_name}_cbc_encrypted.bmp", original_shape, "CBC Encrypted")
    else:
        print(f"Warning: {bmp_file} not found, cannot display images.")
    
    
