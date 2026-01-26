import Crypto
import random
from Crypto.Cipher import AES
import Crypto.Hash.SHA256
from Crypto.Util.number import getPrime, GCD, bytes_to_long, long_to_bytes


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no inverse exists")
    return x % m


def pkcs7_pad(msg, block_size=16):
    pad_len = block_size - (len(msg) % block_size)
    return msg + bytes([pad_len] * pad_len)


def pkcs7_unpad(msg):
    pad_len = msg[-1]
    if pad_len < 1 or pad_len > 16:
        return msg
    return msg[:-pad_len]


def sha256_16_bytes(x_int):
    h = Crypto.Hash.SHA256.new()
    h.update(str(x_int).encode())
    return bytes(h.hexdigest()[:16].encode())


def aes_cbc_encrypt(key16, iv16, msg_bytes):
    cipher = AES.new(key16, AES.MODE_CBC, iv=iv16)
    return cipher.encrypt(pkcs7_pad(msg_bytes, 16))


def aes_cbc_decrypt(key16, iv16, ct_bytes):
    cipher = AES.new(key16, AES.MODE_CBC, iv=iv16)
    return pkcs7_unpad(cipher.decrypt(ct_bytes))


# "textbook" RSA
def rsa_keygen(prime_bits=1024, e=65537):
    # Generate two primes; ensure gcd(e, phi(n)) == 1
    while True:
        p = getPrime(prime_bits)
        q = getPrime(prime_bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            n = p * q
            d = modinv(e, phi)
            return (n, e, d, p, q, phi)


def rsa_encrypt(m_int, n, e):
    if not (0 <= m_int < n):
        raise ValueError("message must be an integer in Z_n (less than n)")
    return pow(m_int, e, n)


def rsa_decrypt(c_int, n, d):
    return pow(c_int, d, n)


print("Task 3 Part 1: textbook RSA (keygen + encrypt/decrypt)")

n, e, d, p, q, phi = rsa_keygen(prime_bits=1024, e=65537)
print("Generated RSA parameters:")
print("n (bits):", n.bit_length())
print("e:", e)
print("d (bits):", d.bit_length())

msg1 = b"Hello RSA"
m1 = bytes_to_long(msg1)
c1 = rsa_encrypt(m1, n, e)
m1_dec = rsa_decrypt(c1, n, d)
print("\nMessage 1:", msg1)
print("m1 (int):", m1)
print("c1:", c1)
print("decrypted:", long_to_bytes(m1_dec))

msg2 = b"Another message to encrypt"
m2 = bytes_to_long(msg2)
c2 = rsa_encrypt(m2, n, e)
m2_dec = rsa_decrypt(c2, n, d)
print("\nMessage 2:", msg2)
print("m2 (int):", m2)
print("c2:", c2)
print("decrypted:", long_to_bytes(m2_dec))
