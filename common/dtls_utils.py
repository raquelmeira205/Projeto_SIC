from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def dtls_hkdf_expand_label(secret, label, context, length):
    """
    Implementação simplificada de HKDF-Expand-Label para DTLS.
    """
    # Info = Length(2) | LabelLen(1) | Label | ContextLen(1) | Context
    # Label prefixado com "dtls13 "
    full_label = b"dtls13 " + label
    
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
    Deriva as chaves para AES-GCM (Key e IV/Salt) a partir do Master Secret.
    Retorna: client_write_key, server_write_key, client_write_iv, server_write_iv
    """
    key_len = 16 # AES-128
    iv_len = 4   # Salt parte do IV
    
    total_bytes = (key_len + iv_len) * 2
    
    # Semente HKDF
    seed = server_random + client_random
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=total_bytes,
        salt=None,
        info=b"key expansion" + seed,
        backend=default_backend()
    )
    key_block = hkdf.derive(master_secret)
    
    # Divide o bloco de chaves
    client_write_key = key_block[0:16]
    server_write_key = key_block[16:32]
    client_write_iv = key_block[32:36]
    server_write_iv = key_block[36:40]
    
    return client_write_key, server_write_key, client_write_iv, server_write_iv
