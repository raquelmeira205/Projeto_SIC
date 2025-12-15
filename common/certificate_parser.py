
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from .nid_types import NID

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

def read_nid_from_cert(cert):
    """
    Reads NID from certificate subject serial number.
    cert: x509.Certificate object or path
    """
    if isinstance(cert, str):
        cert = load_cert(cert)
        
    nid_attributes = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    
    if not nid_attributes:
        raise ValueError("NID not found in certificate (Subject SerialNumber missing).")
        
    nid_str = nid_attributes[0].value
    
    return NID(nid_str)

def verify_cert_signature(cert, ca_cert):
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA512())
        )
        return True
    except Exception as e:
        raise ValueError(f"Certificate verification failed: {e}")
