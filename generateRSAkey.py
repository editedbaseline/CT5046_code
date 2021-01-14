'''
Generate RSA keys
CT5046

https://www.pycryptodome.org/en/latest/src/examples.html#generate-an-rsa-key
https://stackoverflow.com/questions/56923762/crypto-cipher-aes-mode-eax-encrypt-and-digest-error-argument-2-must-be-bytes-n

The Crypto module must be pycryptodome (not pycrypto, and it won't run it both are installed)
'''

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# Generate keys
key = RSA.generate(2048)
session_key = get_random_bytes(16)
print(key)

# Plaintext as UTF-8
strPlaintext = b'RSA encryption is easy'

# Encrypt session key with RSA public key
cipher_rsa = PKCS1_OAEP.new(key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt data with session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(strPlaintext)

# Print ciphertext
print("Ciphertext is", ciphertext)
