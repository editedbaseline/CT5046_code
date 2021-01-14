# Generate RSA keys

from Crypto.PublicKey import RSA
from Crypto import Random

# Get random number
random_generator = Random.new().read

# Generate key pair
key = RSA.generate(1024, random_generator)
print(key)

# Represent plaintext as byte string
strPlaintext = b'RSA encryption is easy'

# Get public key
key_public = key.publickey()

# Encrypt the plaintext using it
strCiphertext = key_public.encrypt(strPlaintext, 32)
print(strCiphertext)

# Decrypt ciphertext
strDecryptedText = key.decrypt(strCiphertext)
print(strCiphertext)