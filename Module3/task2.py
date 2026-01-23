import Crypto
import math
import random
from Crypto.Cipher import AES
import Crypto.Hash.SHA256

q = int.from_bytes(b'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371')
a = int.from_bytes(b'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5')

alice_rand = random.randrange(1, q)     #each party gets a random private key
bob_rand = random.randrange(1, q)

alice_y = pow(a, alice_rand, q)     #each party computes their public key
bob_y = pow(a, bob_rand, q)


#---------------------------Mallory intercepts, sending q instead of alice_y and bob_y

print('Mallory intercepted, sending q instead of Ya and Yb')

alice_s = pow(q, alice_rand, q)     #computing s for both parties
bob_s = pow(q, bob_rand, q)

print('Alice computes shared key s: ', alice_s)
print('Bob computes his shared key s: ', bob_s)
print('The key is 0 because q^n mod q = 0 for all n!\n')

alice_SHA = Crypto.Hash.SHA256.new()        #public key computation
alice_SHA.update(str(alice_s).encode()) 

bob_SHA = Crypto.Hash.SHA256.new()
bob_SHA.update(str(bob_s).encode())         #public key computation

mallory_SHA = Crypto.Hash.SHA256.new()
mallory_SHA.update('0'.encode())

print('Alice SHA:   ',alice_SHA.hexdigest())
print('Bob SHA:     ',bob_SHA.hexdigest())          #view that the two are identical
print('Mallory SHA: ',mallory_SHA.hexdigest())

print('Mallory, knowing that the shared key is 0, can compute the same SHA\n')
alice_key = bytes(alice_SHA.hexdigest()[:16].encode())
bob_key = bytes(bob_SHA.hexdigest()[:16].encode())      #shortened key for AES
mallory_key = bytes(mallory_SHA.hexdigest()[:16].encode())


print('Now Alice is going to send a message to Bob')
msg = bytes('Hello, this is an encrypted message from Alice'.encode())
print('original message:', msg)

alice_cipher = AES.new(alice_key, AES.MODE_ECB)
bob_cipher = AES.new(bob_key, AES.MODE_ECB)     #both parties create ciphers to use on their own
mallory_cipher = AES.new(mallory_key, AES.MODE_ECB)


pad_len = 16 - (len(msg) % 16)
msg_padded = msg + bytes([pad_len] * pad_len)   #PCKS#7 padding

secret = alice_cipher.encrypt(msg_padded)
print('encrypted message (with Alice\'s cipher):    ',secret)

print('decrypted message (with Mallory\'s cipher): ', mallory_cipher.decrypt(secret))
#print('decrypted message(with Bob\'s cipher):       ', bob_cipher.decrypt(secret))

hexdigest=alice_SHA.hexdigest()
print('\nMallory can successfully breach Alice and Bob\'s confidentiality')