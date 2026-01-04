from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

def extract_nid_from_cert(cert):
    """
    Extrai o NID (serial number no Subject) de um objeto Certificate.
    Retorna 16 bytes.
    """
    nid_attributes = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    
    if not nid_attributes:
        raise ValueError("NID não encontrado no certificado (Subject SerialNumber faltando).")
        
    nid_str = nid_attributes[0].value
    
    try:
        nid_int = int(nid_str)
        nid_bytes = nid_int.to_bytes(16, 'big')
    except ValueError:
        try:
            nid_bytes = bytes.fromhex(nid_str)
            if len(nid_bytes) != 16:
                    if len(nid_bytes) < 16:
                        nid_bytes = nid_bytes.rjust(16, b'\x00')
                    else:
                        nid_bytes = nid_bytes[:16]
        except:
            raise ValueError(f"Formato de NID inválido no certificado: {nid_str}")

    return nid_bytes

def read_nid_from_cert(cert_path):
    """
    Lê o NID (serial number no Subject) do arquivo de certificado e retorna 16 bytes.
    """
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return extract_nid_from_cert(cert)

    except Exception as e:
        print(f"[PKI] Erro ao ler certificado {cert_path}: {e}")
        return None
