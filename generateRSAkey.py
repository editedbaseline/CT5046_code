'''
Generate RSA keys
CT5046
Andrew Carr

Tested and working on:
- Windows 10 with Python 3.9.1
- Windows 10 WSL Ubunbu with 3.8.5

Pre-req's:
- make sure pycrypto is NOT installed (pip uninstall pycrypto)
- pycryptodome (pip install pycryptodome)

Credit:
    https://www.pycryptodome.org/en/latest/src/examples.html#generate-an-rsa-key
    https://stackoverflow.com/questions/56923762/crypto-cipher-aes-mode-eax-encrypt-and-digest-error-argument-2-must-be-bytes-n
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
