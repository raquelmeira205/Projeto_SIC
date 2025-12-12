from common.security_handshake import SecurityHandshake
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SecurityWrapper(SecurityHandshake):
    def __init__(self, cert_path, key_path, ca_cert_path, sink_cert_path=None):
        super().__init__(cert_path, key_path, ca_cert_path)
        self.sink_cert = None
        if sink_cert_path:
            self.sink_cert = self._load_cert(sink_cert_path)

    def sign_data(self, data):
        """Signs arbitrary data using the local private key."""
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA512())
        )
        return signature

    def verify_sink_signature(self, data, signature):
        """Verifies data signed by the Sink."""
        if not self.sink_cert:
            print("[Sec] Erro: Certificado do Sink não carregado.")
            return False
            
        try:
            self.sink_cert.public_key().verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA512())
            )
            return True
        except Exception as e:
            print(f"[Sec] Falha na verificação da assinatura do Sink: {e}")
            return False
