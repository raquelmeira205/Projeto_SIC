from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def dtls_hkdf_expand_label(secret, label, context, length):
    """
    HKDF-Expand-Label from TLS 1.3 / (used loosely here for simplicity)
    Or TLS 1.2 PRF?
    Let's stick to a simple HKDF since we are "Simplified DTLS".
    """
    # Info = Length(2) | LabelLen(1) | Label | ContextLen(1) | Context
    # Label is usually "tls " + label
    full_label = b"dtls13 " + label
    
    info = len(length.to_bytes(2, 'big')) # ? No this creates bytes.
    info = length.to_bytes(2, 'big')
    info += len(full_label).to_bytes(1, 'big')
    info += full_label
    info += len(context).to_bytes(1, 'big')
    info += context
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(secret)

def derive_key_material(master_secret, server_random, client_random):
    """
    Derive keys for AES-GCM (16 key + 4 salt usually) from Master Secret.
    """
    # 2 keys * 16 bytes + 2 IVs * 4 bytes = 40 bytes? 
    # AES-GCM explicit nonce is 8 bytes, salt is 4.
    key_len = 16
    iv_len = 4 # Static part (Salt)
    
    total_bytes = (key_len + iv_len) * 2
    
    # We use HKDF to expand master_secret into key_block
    # seed = server_random + client_random
    seed = server_random + client_random
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=total_bytes,
        salt=None,
        info=b"key expansion" + seed, # Simple info
        backend=default_backend()
    )
    key_block = hkdf.derive(master_secret)
    
    # Split
    client_write_key = key_block[0:16]
    server_write_key = key_block[16:32]
    client_write_iv = key_block[32:36]
    server_write_iv = key_block[36:40]
    
    return client_write_key, server_write_key, client_write_iv, server_write_iv
