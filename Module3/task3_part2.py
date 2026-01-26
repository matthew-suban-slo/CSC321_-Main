import random
from Crypto.Util.number import GCD
from task3 import (
    rsa_keygen, rsa_encrypt, rsa_decrypt,
    sha256_16_bytes, aes_cbc_encrypt, aes_cbc_decrypt
)


# T3P2: MITM key fixing via (textbook RSA) malleability/substitution
print("Task 3 Part 2: MITM key fixing via (textbook RSA) malleability/substitution")
# - Alice: owns RSA keypair (n,e,d), will decrypt a ciphertext to recover s and derive AES key k
# - Bob: chooses random s in Z*_n, encrypts with Alice's public key and sends c
# - Mallory: intercepts and substitutes ciphertext so Alice's recovered s is known to Mallory

n, e, d, p, q, phi = rsa_keygen(prime_bits=1024, e=65537)
print("Alice's RSA parameters:")
print("n (bits):", n.bit_length())
print("e:", e)

iv = bytes([0] * 16)  # fixed IV (as allowed by assignment)

# Bob chooses session secret s in Z*_n
while True:
    s = random.randrange(2, n - 1)
    if GCD(s, n) == 1:
        break

c = rsa_encrypt(s, n, e)
print("\nBob chose secret s (hidden from Alice/Mallory initially).")
print("Bob sends ciphertext c = s^e mod n.")

# Mallory substitutes c' for c. Easiest "key fixing": force s' = 1 by sending c' = 1^e mod n = 1.
c_prime = 1
forced_s = 1
print("\nMallory intercepts c and sends c' =", c_prime, "instead.")
print("Because RSA decrypt is m = c^d mod n, Alice will recover s' =", forced_s)

# Alice decrypts what she received
s_alice = rsa_decrypt(c_prime, n, d)
print("\nAlice decrypts c' and computes s' =", s_alice)

# Alice derives symmetric key and encrypts a message to Bob
k_alice = sha256_16_bytes(s_alice)
m = b"Hi Bob! (sent under key derived from s')"
c0 = aes_cbc_encrypt(k_alice, iv, m)
print("Alice derives k = SHA256(s') truncated to 16 bytes and AES-CBC encrypts m.")
print("Ciphertext c0:", c0)

# Mallory can derive the same key because Mallory knows s' (forced)
k_mallory = sha256_16_bytes(forced_s)
m_recovered = aes_cbc_decrypt(k_mallory, iv, c0)
print("\nMallory computes the same k (since she forced s') and decrypts c0:")
print("Recovered m:", m_recovered)

print("\nAnother malleability example (integrity disruption):")
print("- In textbook RSA, an attacker can replace a ciphertext with an encryption of a different value,")
print("  causing the receiver to derive the wrong key / wrong plaintext without any detection.")


# -------------------- RSA signature malleability demo --------------------
print("\nTask 3 Part 2 (extra): RSA signature malleability")
print("Signature scheme: Sign(m,d) = m^d mod n  (textbook / insecure)")

# Pick two messages in Z*_n
while True:
    m1_sig = random.randrange(2, n - 1)
    m2_sig = random.randrange(2, n - 1)
    if GCD(m1_sig, n) == 1 and GCD(m2_sig, n) == 1:
        break

sig1 = pow(m1_sig, d, n)
sig2 = pow(m2_sig, d, n)

m3 = (m1_sig * m2_sig) % n
sig3_forged = (sig1 * sig2) % n

v1 = pow(sig1, e, n)
v2 = pow(sig2, e, n)
v3 = pow(sig3_forged, e, n)

print("m1:", m1_sig)
print("m2:", m2_sig)
print("m3 = (m1*m2) mod n:", m3)
print("\nVerify signatures by raising to e mod n:")
print("sig1^e mod n == m1 ?", v1 == m1_sig)
print("sig2^e mod n == m2 ?", v2 == m2_sig)
print("forged sig3 = sig1*sig2 mod n")
print("sig3^e mod n == m3 ?", v3 == m3)
