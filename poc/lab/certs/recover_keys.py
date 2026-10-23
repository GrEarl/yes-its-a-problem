#!/usr/bin/env python3
"""Recover the 8 compromised eMudhra P-384 intermediate private keys.

The keys were generated with a broken procedure: the 384-bit private scalars
are actually tiny integers (< 256).  They are recovered by brute-force:
compute 1*G, 2*G, ... until the public point matches.

Usage:
    python3 recover_keys.py <cert.pem> [<cert.pem> ...]
Writes <name>.key.pem next to each input certificate.
"""
import sys, os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# secp384r1 base point
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
A  = P - 3
GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
G = (GX, GY)

def add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1,y1=Pt; x2,y2=Qt
    if x1==x2 and (y1+y2)%P==0: return None
    if Pt==Qt: l=(3*x1*x1+A)*pow(2*y1,-1,P)%P
    else:      l=(y2-y1)*pow(x2-x1,-1,P)%P
    x3=(l*l-x1-x2)%P
    return (x3,(l*(x1-x3)-y1)%P)

def pub_point(cert_path):
    with open(cert_path, 'rb') as fh:
        c = x509.load_pem_x509_certificate(fh.read())
    pk = c.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey): return None
    return pk.public_numbers().x, pk.public_numbers().y

def recover(cert_path):
    tgt = pub_point(cert_path)
    if tgt is None:
        print(cert_path, "not EC"); return None
    Q = G
    for d in range(1, 300):
        if Q == tgt:
            priv = ec.derive_private_key(d, ec.SECP384R1())
            pem = priv.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            base = os.path.basename(cert_path)
            out = os.path.join(os.path.dirname(cert_path) or '.',
                               base.replace('.crt.pem','').replace('.pem','') + '.key.pem')
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as fh:
                fh.write(pem)
            print(f"{os.path.basename(cert_path):35s}  d = {d:3d} (0x{d:02x})  -> {out}")
            return d
        Q = add(Q, G)
    print(cert_path, "not a tiny key (>300)"); return None

if __name__ == '__main__':
    for f in sys.argv[1:]:
        recover(f)
