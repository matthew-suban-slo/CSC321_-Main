import Crypto
import math
import random
from Crypto.Cipher import AES
import Crypto.Hash.SHA256


def sha(data):
    return Crypto.Hash.SHA256.new(data).hexdigest()

def trunc_hash(hash_string, bits):
    hex_chars = bits // 4
    truncated = hash_string[:hex_chars]
    value = int(truncated, 16)
    bitmask = (1 << bits) - 1
    return value & bitmask
    
def hamming_distance(s1, s2):
    dist = 0
    for i in range(len(s1)):
        if s1[i] != s2[i]:
            dist += 1
    return dist

def find_hamming_dist_1():
    base = ''.join(chr(random.randint(33, 126)) for _ in range(10))
    for i in range(len(base)):
        orig = ord(base[i])
        flipped = orig ^ (1 << i)
        modified = base[:i] + chr(flipped) + base[i+1:]
        if(hamming_distance(base, modified) == 1):
            return base, modified
    return None, None



while(1):
    data = input()
    shaa = sha(data.encode())
    for bits in [4, 8, 16, 32, 64]:
        print('trunc_sha: ',trunc_hash(shaa, bits))
        print(find_hamming_dist_1())