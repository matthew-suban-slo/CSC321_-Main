#!/usr/bin/env python3
"""
Task 2: Limits of Confidentiality - CBC Oracle and Bit-Flip Exploit

This module implements:
- submit() oracle function: Takes user input, sanitizes it, and encrypts with AES-128-CBC
- verify() oracle function: Decrypts ciphertext and checks for ";admin=true;" pattern
- CBC bit-flip exploit: Modifies ciphertext to bypass sanitization and inject ";admin=true;"

Based on the vulnerability that flipping bits in ciphertext block c_i scrambles plaintext block m_i
but flips the same bit in plaintext block m_{i+1}.

Usage:
    python task2_cbc_oracle.py
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size is 16 bytes (128 bits)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    PKCS#7 padding implementation.
    Pads data to be a multiple of block_size.
    """
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    PKCS#7 unpadding implementation.
    Removes padding from padded data.
    """
    if len(padded) == 0 or len(padded) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return padded[:-pad_len]


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """
    Encrypts a single 16-byte block using AES-128 in ECB mode.
    This is used as a primitive for CBC mode implementation.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("aes_ecb_encrypt_block takes a single 16-byte block")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    """
    Decrypts a single 16-byte block using AES-128 in ECB mode.
    This is used as a primitive for CBC mode implementation.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("aes_ecb_decrypt_block takes a single 16-byte block")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


def aes_manual_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """
    Manual implementation of AES-128-CBC encryption.
    Encrypts plaintext block-by-block using CBC mode.
    """
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = b''
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = aes_ecb_encrypt_block(key, xored)
        ciphertext += enc
        prev = enc
    return ciphertext


def aes_manual_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Manual implementation of AES-128-CBC decryption.
    Decrypts ciphertext block-by-block using CBC mode.
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    plaintext_padded = b''
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        dec = aes_ecb_decrypt_block(key, block)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext_padded += plain_block
        prev = block
    return pkcs7_unpad(plaintext_padded, BLOCK_SIZE)


class CBCServerOracle:
    
    def __init__(self):
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)
    
    def _sanitize(self, s: str) -> str:
        return s.replace(";", "%3B").replace("=", "%3D")
    
    def submit(self, userdata: str) -> bytes:

        prefix = "userid=456;userdata="
        suffix = ";session-id=31337"

        
        sanitized = self._sanitize(userdata)
        full = (prefix + sanitized + suffix).encode('utf-8')
        ct = aes_manual_cbc_encrypt(self.key, full, self.iv)
        return self.iv + ct
    
    def verify(self, iv_and_ciphertext: bytes) -> bool:
        if len(iv_and_ciphertext) < BLOCK_SIZE:
            return False
        iv = iv_and_ciphertext[:BLOCK_SIZE]
        ct = iv_and_ciphertext[BLOCK_SIZE:]
        try:
            pt = aes_manual_cbc_decrypt(self.key, ct, iv)
        except Exception as e:
            print(f"Decrypt error: {e}")
            return False
        pt_str = pt.decode('utf-8', errors='replace')
        # Check for the admin pattern
        print('----------------------------')
        print(f'Decrypted plaintext: {pt_str}')
        return ";admin=true;" in pt_str


def cbc_bitflip_exploit(server: CBCServerOracle) -> tuple[bytes, bool]:
    """
    Exploits CBC mode vulnerability to inject ";admin=true;" into the plaintext.
    
    The exploit works by:
    1. Crafting userdata so that a controlled region aligns at a block boundary
    2. Submitting placeholder characters that will be sanitized
    3. Modifying the previous ciphertext block (or IV) to flip bits in the next plaintext block
    4. This causes the placeholder to become ";admin=true;" after decryption
    
    Key insight: In CBC mode, flipping bit j in ciphertext block c_i will:
    - Scramble plaintext block m_i (unusable)
    - Flip bit j in plaintext block m_{i+1} (controllable!)
    
    Returns: (forged_iv_and_ciphertext, success)
    """
    prefix = "userid=456;userdata="
    target = ";admin=true;"  # what we want to appear in the decrypted plaintext

    prefix_len = len(prefix)
    pad_len = (-prefix_len) % BLOCK_SIZE  # bytes needed so next byte starts new block
    userdata_prefix = "A" * pad_len

    # Placeholders that will later be flipped into ";admin=true;"
    placeholder = "?" * len(target)
    userdata = userdata_prefix + placeholder

    iv_and_ct = server.submit(userdata)
    iv = iv_and_ct[:BLOCK_SIZE]
    ct = bytearray(iv_and_ct[BLOCK_SIZE:])

    session_suffix = ";session-id=31337"
    full_plain_before = (
        prefix + server._sanitize(userdata) + session_suffix
    ).encode("utf-8")

    placeholder_bytes = server._sanitize(placeholder).encode("utf-8")
    idx = full_plain_before.find(placeholder_bytes)
    if idx == -1:
        raise RuntimeError(
            "Could not locate placeholder in constructed plaintext (alignment failed)"
        )

    # Determine which block and position within that block contain the placeholder.
    block_index = idx // BLOCK_SIZE
    pos_in_block = idx % BLOCK_SIZE

    if block_index == 0:
        prev_block = bytearray(iv)
    else:
        start_prev = (block_index - 1) * BLOCK_SIZE
        end_prev = block_index * BLOCK_SIZE
        prev_block = bytearray(ct[start_prev:end_prev])

    # Extract the original plaintext block that currently holds the placeholder.
    original_block = full_plain_before[
        block_index * BLOCK_SIZE : (block_index + 1) * BLOCK_SIZE
    ]

    modified_prev = bytearray(prev_block)
    for i in range(len(placeholder_bytes)):
        orig_b = original_block[pos_in_block + i]
        desired_b = ord(target[i])
        delta = orig_b ^ desired_b
        modified_prev[pos_in_block + i] ^= delta

    if block_index == 0:
        new_iv = bytes(modified_prev)
        new_ct = bytes(ct)
    else:
        new_ct_array = bytearray(ct)
        start_prev = (block_index - 1) * BLOCK_SIZE
        new_ct_array[start_prev : start_prev + BLOCK_SIZE] = modified_prev
        new_ct = bytes(new_ct_array)
        new_iv = iv

    forged = new_iv + new_ct
    success = server.verify(forged)
    return forged, success


if __name__ == "__main__":
    # Initialize server oracle
    server = CBCServerOracle()
    print(f"\nCBCServerOracle initialized with random key and IV")
    print(f"Key length: {len(server.key)} bytes")
    print(f"IV length: {len(server.iv)} bytes")
    print("\n")
    
    # Test 1: Normal submission (should not pass verify)
    print("Test 1: Normal user submission")

    normal_userdata = "normal_user_data"
    ct_normal = server.submit(normal_userdata)

    print(f"User submitted: '{normal_userdata}'")
    print(f"Ciphertext length: {len(ct_normal)} bytes")
    print(f"verify(original): {server.verify(ct_normal)}")
    print("As expected, normal input cannot inject ';admin=true;'")
    print("\n")
    
    # Test 2: Attempt direct injection (should fail due to sanitization)
    print("Test 2: Attempt direct injection")    
    malicious_userdata = "test;admin=true;test"
    ct_malicious = server.submit(malicious_userdata)
    print(f"User submitted: '{malicious_userdata}'")
    print(f"verify(malicious): {server.verify(ct_malicious)}")
    print("Sanitization prevents direct injection")
    print("\n")
    
    # Test 3: CBC bit-flip exploit
    print("Test 3: CBC Bit-Flip Exploit")
    print("Attempting to exploit CBC mode vulnerability...")
    try:
        forged, success = cbc_bitflip_exploit(server)
        if success:
            print("EXPLOIT SUCCESSFUL!")
            print(f"Forged ciphertext length: {len(forged)} bytes")
            print(f"verify(forged): {server.verify(forged)}")
            # The exploit successfully bypassed sanitization by:
            #   1. Aligning userdata at a block boundary
            #   2. Using placeholder characters that won't be sanitized
            #   3. Modifying the previous ciphertext block to flip bits
            #   4. This caused the placeholder to become ';admin=true;' after decryption
        else:
            print("  - check alignment and block boundaries")
    except Exception as e:
        print(f"Exploit error: {e}")
    print("\n")
    
    print("Task 2 complete")
