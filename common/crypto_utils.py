import hmac
import hashlib

def generate_mac(key: bytes, data: bytes) -> bytes:
    """
    Gera um HMAC-SHA256 para os dados fornecidos usando a chave.
    
    Args:
        key (bytes): Chave secreta (ex: Chave de Sessão).
        data (bytes): Dados a autenticar.
        
    Returns:
        bytes: MAC de 32 bytes de acordo com SHA-256.
    """
    if not isinstance(key, bytes) or not isinstance(data, bytes):
        raise TypeError("Chave e dados devem ser do tipo bytes")
        
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()

def verify_mac(key: bytes, data: bytes, received_mac: bytes) -> bool:
    """
    Verifica se o MAC recebido corresponde aos dados e chave.
    Utiliza comparação de tempo constante para segurança.
    
    Args:
        key (bytes): Chave secreta.
        data (bytes): Dados recebidos.
        received_mac (bytes): MAC recebido para verificação.
        
    Returns:
        bool: True se válido, False caso contrário.
    """
    try:
        expected_mac = generate_mac(key, data)
        return hmac.compare_digest(expected_mac, received_mac)
    except Exception:
        return False
