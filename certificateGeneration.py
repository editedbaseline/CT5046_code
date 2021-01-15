from __future__ import print_function, unicode_literals
from datetime import datetime, timedelta
from OpenSSL import crypto

# Load private key
ftype = crypto.FILETYPE_PEM
with open('cert.key', 'rb') as f:
    k = f.read()
k = crypto.load_privatekey(ftype, k)

now = datetime.now()
expire = now + timedelta(days=365)

# Generate cert
cert = crypto.X509()
cert.get_subject().C = 'UK'                 # Country
cert.get_subject().ST = 'Cumbria'           # State
cert.get_subject().L = 'Carlisle'           # Locality
cert.get_subject().O = 'Baseline'           # Org
cert.get_subject().OU = 'IT'                # Org unit
cert.get_subject().CN = 'EditedBaseline'    # Common name

cert.set_serial_number(1000)
cert.set_notBefore(now.strftime('%Y%m%d%H%M%SZ').encode())
cert.set_notAfter(expire.strftime('%Y%m%d%H%M%SZ').encode())
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha256')

with open('cert.pem', 'wb') as f:
    f.write (crypto.dump_certificate(ftype, cert))
    