
import logging
from cryptography.hazmat.primitives import serialization
from .security_primitives import generate_ephemeral_key, sign_data, verify_signature, derive_session_key
from .certificate_parser import verify_cert_signature, load_cert

class BLEConnectionWrapper:
    def __init__(self, connection_backend, local_cert, local_key, ca_cert):
        """
        connection_backend: Object with send(bytes) and receive() -> bytes methods
        """
        self.connection = connection_backend
        self.local_cert = local_cert
        self.local_key = local_key
        self.ca_cert = ca_cert
        self.session_key = None
        self.peer_cert = None

    def perform_handshake(self):
        logging.info("Starting Handshake...")
        
        # 1. Exchange Certificates
        my_cert_pem = self.local_cert.public_bytes(serialization.Encoding.PEM)
        self.connection.send(my_cert_pem)
        
        peer_cert_pem = self.connection.receive()
        try:
            # We assume receive returns bytes
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            self.peer_cert = x509.load_pem_x509_certificate(peer_cert_pem, default_backend())
        except Exception as e:
            raise ValueError(f"Failed to parse peer certificate: {e}")

        # 2. Verify Peer Certificate
        verify_cert_signature(self.peer_cert, self.ca_cert)
        
        # 3. Ephemeral Key Exchange
        ephemeral_priv, ephemeral_pub = generate_ephemeral_key()
        
        # Sign ephemeral public key
        pub_bytes = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        signature = sign_data(self.local_key, pub_bytes)
        
        # Send Public Key + Signature
        self.connection.send(pub_bytes)
        self.connection.send(signature)
        
        # Receive Peer Public Key + Signature
        peer_pub_bytes = self.connection.receive()
        peer_signature = self.connection.receive()
        
        # Verify Peer Ephemeral Key Signature
        peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes, default_backend())
        verify_signature(self.peer_cert.public_key(), peer_signature, peer_pub_bytes)
        
        # 4. Derive Session Key
        self.session_key = derive_session_key(ephemeral_priv, peer_pub_key)
        logging.info("Handshake Complete. Session Key Established.")
        
        return self.session_key
