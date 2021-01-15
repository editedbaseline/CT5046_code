from __future__ import print_function, unicode_literals
from OpenSSL import crypto

# Load private key
ftype = crypto.FILETYPE_PEM
with open('cert.key', 'rb') as f:
    key = f.read()

key = crypto.load_privatekey(ftype, key)
req = crypto.X509Req()

alt_name = [b'DNS:www.helloworld.com', 
            b'DNS:doc.helloworld.com',]
key_usage = [b'Digital Signature',
            b'Non Repudiation',
            b'Key Encipherment']

req.get_subject().C = 'UK'                 # Country
req.get_subject().ST = 'Cumbria'           # State
req.get_subject().L = 'Carlisle'           # Locality
req.get_subject().O = 'Baseline'           # Org
req.get_subject().OU = 'IT'                # Org unit
req.get_subject().CN = 'EditedBaseline'    # Common name
req.add_extensions([
    crypto.X509Extension(b'basicConstraints',
                        False,
                        b'CA:FALSE'),
    crypto.X509Extension(b'keyUsage',
                        False,
                        b','.join(key_usage)),
    crypto.X509Extension(b'subjectAltName',
                        False,
                        b','.join(alt_name)),
])

req.set_pubkey(key)
req.sign(key, 'sha256')

csr = crypto.dump_certificate_request(ftype, req)
with open('cert.csr', 'wb') as f:
    f.write(csr)

