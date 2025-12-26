"""
DTLS-Like Session Management

Implements DTLS-style session with:
- ECDH key exchange for forward secrecy
- AES-256-GCM AEAD encryption
- Sequence numbers for replay protection
- Certificate-based mutual authentication
"""

import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import threading


class DTLSSession:
    """
    DTLS-like session for end-to-end encryption.
    
    Manages encryption/decryption with AES-GCM AEAD and replay protection.
    """
    
    def __init__(self, transport, cert_path: str, key_path: str, ca_cert_path: str, 
                 is_server: bool = False):
        """
        Initialize DTLS session.
        
        Args:
            transport: DTLSTransport instance
            cert_path: Path to X.509 certificate
            key_path: Path to private key
            ca_cert_path: Path to CA certificate
            is_server: True for Sink (server), False for Node (client)
        """
        self.transport = transport
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        self.is_server = is_server
        
        # Session state
        self.session_established = False
        self.epoch = 0
        self.send_seq = 0
        self.recv_seq = 0
        self.recv_window = set()  # For replay protection
        self.lock = threading.Lock()
        
        # Cryptographic material
        self.aesgcm = None  # AES-GCM cipher
        self.send_iv_base = None  # Base IV for sending
        self.recv_iv_base = None  # Base IV for receiving
        
        # Handshake transcript (for Finished message)
        self.handshake_transcript = b''
        
        # Load own certificate and key
        self._load_credentials()
    
    def _load_credentials(self):
        """Load certificate, private key, and CA certificate."""
        # Load own certificate
        with open(self.cert_path, 'rb') as f:
            cert_data = f.read()
            self.own_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            self.own_cert_der = self.own_cert.public_bytes(serialization.Encoding.DER)
        
        # Load own private key
        with open(self.key_path, 'rb') as f:
            self.own_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load CA certificate
        with open(self.ca_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    def _verify_certificate(self, cert_der: bytes) -> x509.Certificate:
        """
        Verify peer certificate against CA.
        
        Args:
            cert_der: DER-encoded certificate
            
        Returns:
            Verified certificate object
            
        Raises:
            ValueError: If certificate verification fails
        """
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Verify certificate signature with CA public key
        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        except Exception as e:
            raise ValueError(f"Certificate verification failed: {e}")
        
        return cert
    
    def _perform_ecdh(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform ECDH key exchange.
        
        Args:
            peer_public_key_bytes: Peer's ephemeral ECDH public key
            
        Returns:
            Shared secret
        """
        # Load peer's public key
        peer_public_key = serialization.load_der_public_key(
            peer_public_key_bytes,
            backend=default_backend()
        )
        
        # Perform ECDH
        shared_secret = self.ecdh_private_key.exchange(
            ec.ECDH(),
            peer_public_key
        )
        
        return shared_secret
    
    def _derive_keys(self, shared_secret: bytes, client_random: bytes, server_random: bytes):
        """
        Derive encryption keys from shared secret using HKDF.
        
        Args:
            shared_secret: ECDH shared secret
            client_random: Client's random value
            server_random: Server's random value
        """
        # Combine randoms for key derivation
        key_material = client_random + server_random
        
        # Derive master secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 12 + 12,  # Key (32) + Client IV (12) + Server IV (12)
            salt=None,
            info=b'DTLS-like key expansion',
            backend=default_backend()
        )
        derived = hkdf.derive(shared_secret + key_material)
        
        # Split derived material
        session_key = derived[:32]
        client_iv_base = derived[32:44]
        server_iv_base = derived[44:56]
        
        # Create AES-GCM cipher
        self.aesgcm = AESGCM(session_key)
        
        # Set IV bases based on role
        if self.is_server:
            self.send_iv_base = server_iv_base
            self.recv_iv_base = client_iv_base
        else:
            self.send_iv_base = client_iv_base
            self.recv_iv_base = server_iv_base
        
        print(f"[DTLS Session] Keys derived, session ready")
    
    def encrypt_record(self, plaintext: bytes) -> bytes:
        """
        Encrypt application data into DTLS record.
        
        Args:
            plaintext: Application data to encrypt
            
        Returns:
            Encrypted DTLS record
        """
        if not self.session_established:
            raise RuntimeError("Session not established")
        
        with self.lock:
            # Increment sequence number
            seq = self.send_seq
            self.send_seq += 1
            
            # Construct nonce: IV_base || sequence_number
            nonce = self.send_iv_base + seq.to_bytes(4, 'big')
            
            # Additional authenticated data (AAD): epoch || seq || content_type || version
            from common.dtls_protocol import DTLSMessageType
            aad = struct.pack('!HQBH',
                self.epoch,
                seq,
                DTLSMessageType.APPLICATION_DATA,
                0x0100  # Version 1.0
            )
            
            # Encrypt with AES-GCM
            ciphertext_and_tag = self.aesgcm.encrypt(nonce, plaintext, aad)
            ciphertext = ciphertext_and_tag[:-16]
            tag = ciphertext_and_tag[-16:]
            
            # Create DTLS record
            from common.dtls_protocol import DTLSRecord
            record = DTLSRecord(
                epoch=self.epoch,
                sequence_number=seq,
                content_type=DTLSMessageType.APPLICATION_DATA,
                version=0x0100,
                ciphertext=ciphertext,
                auth_tag=tag
            )
            
            return record.pack()
    
    def decrypt_record(self, record_bytes: bytes) -> bytes:
        """
        Decrypt DTLS record to plaintext.
        
        Args:
            record_bytes: Encrypted DTLS record
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If decryption fails or replay detected
        """
        if not self.session_established:
            raise RuntimeError("Session not established")
        
        # Unpack record
        from common.dtls_protocol import DTLSRecord
        record = DTLSRecord.unpack(record_bytes)
        
        with self.lock:
            # Replay protection: check sequence number
            if record.sequence_number <= self.recv_seq:
                raise ValueError(f"Replay detected: seq {record.sequence_number} <= {self.recv_seq}")
            
            # Check if already received (sliding window)
            if record.sequence_number in self.recv_window:
                raise ValueError(f"Duplicate sequence number: {record.sequence_number}")
            
            # Construct nonce
            nonce = self.recv_iv_base + record.sequence_number.to_bytes(4, 'big')
            
            # Reconstruct AAD
            import struct
            aad = struct.pack('!HQBH',
                record.epoch,
                record.sequence_number,
                record.content_type,
                record.version
            )
            
            # Decrypt with AES-GCM
            ciphertext_and_tag = record.ciphertext + record.auth_tag
            try:
                plaintext = self.aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
            except Exception as e:
                raise ValueError(f"Decryption failed: {e}")
            
            # Update replay protection
            self.recv_seq = record.sequence_number
            self.recv_window.add(record.sequence_number)
            
            # Keep window size limited (e.g., last 100 packets)
            if len(self.recv_window) > 100:
                self.recv_window = set(sorted(self.recv_window)[-100:])
            
            return plaintext
    
    def send_secure(self, plaintext: bytes) -> bool:
        """
        Encrypt and send data.
        
        Args:
            plaintext: Data to send
            
        Returns:
            True if successful
        """
        try:
            encrypted_record = self.encrypt_record(plaintext)
            self.transport.send(encrypted_record)
            return True
        except Exception as e:
            print(f"[DTLS Session] Send error: {e}")
            return False
    
    def receive_secure(self, timeout: float = None) -> bytes:
        """
        Receive and decrypt data.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Decrypted plaintext
        """
        encrypted_record = self.transport.recv(timeout=timeout)
        return self.decrypt_record(encrypted_record)
    
    def close(self):
        """Close session."""
        self.session_established = False
        self.aesgcm = None
        print("[DTLS Session] Session closed")
