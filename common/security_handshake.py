from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class SecurityHandshake:
    """Implementa o protocolo de handshake de segurança simplificado."""
    
    def __init__(self, cert_path, key_path, ca_cert_path, crl_manager=None):
        """
        Inicializa o handshake.
        
        :param cert_path: Caminho do certificado local.
        :param key_path: Caminho da chave privada local.
        :param ca_cert_path: Caminho do certificado da CA.
        :param crl_manager: Gerenciador de CRL (opcional).
        """
        self.cert = self._load_cert(cert_path)
        self.private_key = self._load_key(key_path)
        self.ca_cert = self._load_cert(ca_cert_path)
        self.crl_manager = crl_manager

        self.peer_cert = None
        self.session_key = None
        self.ephemeral_private_key = None
        self.ephemeral_public_key = None
        self.peer_ephemeral_public_key = None

    def _load_cert(self, path):
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def _load_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    def exchange_certificates(self, connection):
        """Troca certificados com o par."""
        my_cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        connection.send(my_cert_pem)
        peer_cert_pem = connection.receive()
        self.peer_cert = x509.load_pem_x509_certificate(peer_cert_pem, default_backend())

    def verify_peer_certificate(self):
        """Verifica a validade e revogação do certificado do par."""
        if not self.peer_cert:
            raise ValueError("Nenhum certificado do par disponível")

        try:
            self.ca_cert.public_key().verify(
                self.peer_cert.signature,
                self.peer_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA512())
            )
        except Exception as e:
            raise ValueError(f"Falha ao verificar certificado: {e}")

        if self.crl_manager:
            if self.crl_manager.is_revoked(self.peer_cert.serial_number):
                raise ValueError(f"CERTIFICADO REVOGADO! Serial: {self.peer_cert.serial_number}")

        return True

    def generate_ephemeral_key(self):
        """Gera par de chaves efémeras para ECDH."""
        self.ephemeral_private_key = ec.generate_private_key(ec.SECP521R1())
        self.ephemeral_public_key = self.ephemeral_private_key.public_key()

    def sign_ephemeral_key(self):
        """Assina a chave pública efémera com a chave de longa duração."""
        pub_bytes = self.ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        signature = self.private_key.sign(pub_bytes, ec.ECDSA(hashes.SHA512()))
        return pub_bytes, signature

    def verify_peer_ephemeral_key(self, peer_pub_bytes, signature):
        """Verifica a assinatura da chave efémera do par."""
        if not self.peer_cert:
            raise ValueError("Certificado do par não carregado")

        try:
            self.peer_cert.public_key().verify(
                signature,
                peer_pub_bytes,
                ec.ECDSA(hashes.SHA512())
            )
            self.peer_ephemeral_public_key = serialization.load_pem_public_key(
                peer_pub_bytes, default_backend()
            )
        except Exception as e:
            raise ValueError(f"Falha ao verificar chave efémera do par: {e}")

    def derive_session_key(self):
        """Deriva a chave de sessão usando ECDH e HKDF."""
        if not self.ephemeral_private_key or not self.peer_ephemeral_public_key:
            raise ValueError("Chaves efémeras não trocadas")

        shared_secret = self.ephemeral_private_key.exchange(
            ec.ECDH(), self.peer_ephemeral_public_key
        )

        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"sic-protocol-session-key",
            backend=default_backend()
        ).derive(shared_secret)

        return self.session_key

    def perform_handshake(self, connection):
        """Executa todo o fluxo de handshake."""
        self.exchange_certificates(connection)
        self.verify_peer_certificate()
        self.generate_ephemeral_key()

        my_pub_bytes, my_sig = self.sign_ephemeral_key()
        connection.send(my_pub_bytes)
        connection.send(my_sig)

        peer_pub_bytes = connection.receive()
        peer_sig = connection.receive()

        self.verify_peer_ephemeral_key(peer_pub_bytes, peer_sig)

        self.derive_session_key()
        print("[Handshake] Concluído. Chave de sessão estabelecida.")
