from __future__ import print_function, unicode_literals
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

def signer(privkey, data):
    rsakey = RSA.importKey(privkey)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data)
    return signer.sign(digest)

with open('signing.key', 'rb') as f:
    key = f.read()

with open('plaintext.txt', 'rb') as f:
    data = f.read()

sign = signer(key, data)

with open('plaintext.txt.sha256', 'wb') as f:
    f.write(sign)