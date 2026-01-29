import Crypto
import math
import random
from Crypto.Cipher import AES
import Crypto.Hash.SHA256
import time
import pandas as pd
import matplotlib.pyplot as plt

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

def find_collision(bits, max_attempts):
    seen = {}
    start = time.time()
    attempts = 0
    for i in range(max_attempts):
        attempts += 1
        data = ''.join(chr(random.randint(33, 126)) for _ in range(10))
        hash_value = trunc_hash(sha(data.encode()), bits)
        if hash_value in seen:
            elapsed = time.time() - start
            return seen[hash_value], data, attempts, elapsed
        seen[hash_value] = data
    return None, None, max_attempts, time.time() - start

def task_1a():
    print('Task1a: SHA256 hashes of arbitrary inputs')
    for st in ['hello', 'world', 'test', 'SHA256', 'cryptography']:
        print(f'Input: {st}, SHA256: {sha(st.encode())}')

def task_1b():
    print('Task1b: Strings with hamming distance of 1')
    for i in range(1,3):
        base, modified = find_hamming_dist_1()
        print(f'Base: {base}, Modified: {modified}')
        print(f'Base hash: {sha(base.encode())}, Modified hash: {sha(modified.encode())}')

def task_1c():
    print('Task1c: Finding collisions in truncated SHA256 hashes')
    column_names = ['bits','input1', 'input2', 'hash', 'inputs_tried', 'time']
    results = pd.DataFrame(columns=column_names, index = [0])
    results.iloc[0] = [0, '', '', '', 0, 0.0]
    i = 0
    for bits in range(8, 50, 2):
        msg1, msg2, attempts, elapsed = find_collision(bits, 1000000)
        if msg1 and msg2:
            i += 1
            result = pd.DataFrame({'bits':[bits], 'input1':msg1,'input2': msg2, 'hash':trunc_hash(sha(msg1.encode()), bits), 'inputs_tried':attempts, 'time':elapsed})
            results = pd.concat([results, result])
            print(f'Bits: {bits}, Msg1: {msg1}, Msg2: {msg2}, Hash: {trunc_hash(sha(msg1.encode()), bits)}Attempts: {attempts}, Time: {elapsed:.4f}s')
        else:
            print(f'Bits: {bits}, No collision found in {attempts} attempts, Time: {elapsed:.4f}s')
    
    g1 = results.plot.line(x = 'bits', y = 'time', title = 'Digest size vs. Collision time')
    g1.figure.savefig('collision_time.png')
    g2 = results.plot.line(x = 'bits', y = 'inputs_tried', title = 'Digest size vs. Inputs tried')
    g2.figure.savefig('inputs_tried_time.png')

    results.to_csv('task1c_results.csv', index=False)

    
task_1a()
task_1b()
task_1c()

# while(1):
    # data = input()
    # shaa = sha(data.encode())
    # for bits in [4, 8, 16, 32, 64]:
    #     print('trunc_sha: ',trunc_hash(shaa, bits))
    #     print(find_hamming_dist_1())