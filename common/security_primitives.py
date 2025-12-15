
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ephemeral_key():
    # Gera chave efémera ECDH
    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    # Signs data using ECDSA
    return private_key.sign(data, ec.ECDSA(hashes.SHA512()))

def verify_signature(public_key, signature, data):
    # Verifies ECDSA signature
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA512()))

def derive_session_key(private_key, peer_public_key, salt=None, info=b"sic-protocol-session-key"):
    # Deriva a chave de sessão usando ECDH + HKDF
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    ).derive(shared_secret)
    return session_key
