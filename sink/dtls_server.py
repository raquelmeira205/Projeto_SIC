"""
DTLS-like server session management for Sink.

This module implements the server-side DTLS session management,
handling multiple concurrent DTLS sessions with different Nodes.
"""

import secrets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from common.dtls_structs import (
    DtlsContentType, DtlsHandshakeType, DtlsRecord, DtlsHandshakeMessage,
    ClientHello, ServerHello, ClientKeyExchange, Finished
)
from common.dtls_crypto import DtlsCrypto, ReplayWindow

class DtlsServerSession:
    """
    Server-side DTLS session for a single Node.
    
    Manages encryption/decryption and anti-replay for one Node.
    """
    
    def __init__(self, node_nid, sink_nid, cert_path, key_path, ca_cert_path):
        """
        Initialize server-side DTLS session.
        
        Args:
            node_nid: 16-byte Node Network ID
            sink_nid: 16-byte Sink Network ID
            cert_path: Path to Sink certificate
            key_path: Path to Sink private key
            ca_cert_path: Path to CA certificate
        """
        self.node_nid = node_nid
        self.sink_nid = sink_nid
        
        # Load certificates and keys
        self.cert = self._load_cert(cert_path)
        self.private_key = self._load_key(key_path)
        self.ca_cert = self._load_cert(ca_cert_path)
        
        # Session state
        self.established = False
        self.epoch = 0
        self.send_seq = 0
        self.recv_seq = 0
        self.replay_window = ReplayWindow()
        
        # Handshake state
        self.client_random = None
        self.server_random = None
        self.ephemeral_private_key = None
        self.ephemeral_public_key = None
        self.peer_ephemeral_public_key = None
        self.peer_cert = None
        self.handshake_messages = b''
        self.handshake_seq = 0
        
        # Derived keys
        self.master_secret = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None
        
        print(f"[DTLS-Server] Session created for Node {node_nid.hex()[:8]}...")
    
    def _load_cert(self, path):
        """Load X.509 certificate from PEM file"""
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    
    def _load_key(self, path):
        """Load private key from PEM file"""
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    
    def _verify_certificate(self, cert):
        """Verify certificate signature using CA"""
        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA512())
            )
            return True
        except Exception as e:
            print(f"[DTLS-Server] Certificate verification failed: {e}")
            return False
    
    def handle_client_hello(self, handshake_msg):
        """
        Process ClientHello and return ServerHello response.
        
        Returns:
            DTLS record containing ServerHello
        """
        print(f"[DTLS-Server] Processing ClientHello from {self.node_nid.hex()[:8]}...")
        
        # Add to transcript
        self.handshake_messages += handshake_msg
        
        # Unpack handshake message
        msg_type, msg_seq, fragment = DtlsHandshakeMessage.unpack(handshake_msg)
        
        if msg_type != DtlsHandshakeType.CLIENT_HELLO:
            raise ValueError(f"Expected CLIENT_HELLO, got {msg_type}")
        
        # Unpack ClientHello
        client_random, client_nid, ecdh_public_pem = ClientHello.unpack(fragment)
        
        # Verify client NID
        if client_nid != self.node_nid:
            raise ValueError("Client NID mismatch")
        
        self.client_random = client_random
        
        # Load client ECDH public key
        self.peer_ephemeral_public_key = serialization.load_pem_public_key(
            ecdh_public_pem, default_backend()
        )
        
        # Generate server ephemeral ECDH key pair
        self.ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ephemeral_public_key = self.ephemeral_private_key.public_key()
        
        # Generate server random
        self.server_random = secrets.token_bytes(32)
        
        # Serialize ECDH public key and certificate
        ecdh_public_pem = self.ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        
        # Build ServerHello
        server_hello_payload = ServerHello.pack(
            self.server_random,
            self.sink_nid,
            ecdh_public_pem,
            cert_pem
        )
        
        # Wrap in handshake message
        handshake_msg = DtlsHandshakeMessage.pack(
            DtlsHandshakeType.SERVER_HELLO,
            self.handshake_seq,
            server_hello_payload
        )
        self.handshake_seq += 1
        
        # Add to transcript
        self.handshake_messages += handshake_msg
        
        # Wrap in DTLS record
        record = DtlsRecord.pack(
            DtlsContentType.HANDSHAKE,
            0,  # epoch 0 during handshake
            self.send_seq,
            handshake_msg
        )
        self.send_seq += 1
        
        print("[DTLS-Server] ServerHello prepared")
        return record
    
    def handle_client_key_exchange(self, handshake_msg):
        """
        Process ClientKeyExchange and return Finished response.
        
        Returns:
            DTLS record containing Finished
        """
        print(f"[DTLS-Server] Processing ClientKeyExchange from {self.node_nid.hex()[:8]}...")
        
        # Unpack handshake message
        msg_type, msg_seq, fragment = DtlsHandshakeMessage.unpack(handshake_msg)
        
        if msg_type != DtlsHandshakeType.CLIENT_KEY_EXCHANGE:
            raise ValueError(f"Expected CLIENT_KEY_EXCHANGE, got {msg_type}")
        
        # Unpack ClientKeyExchange
        cert_pem, signature = ClientKeyExchange.unpack(fragment)
        
        # Load and verify client certificate
        self.peer_cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        if not self._verify_certificate(self.peer_cert):
            raise ValueError("Client certificate verification failed")
        
        # Verify signature over transcript (before adding this message)
        try:
            self.peer_cert.public_key().verify(
                signature,
                self.handshake_messages,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            raise ValueError(f"Client signature verification failed: {e}")
        
        # Add to transcript AFTER verification
        self.handshake_messages += handshake_msg
        
        # Derive keys
        self._derive_keys()
        
        # Build Finished message
        verify_data = DtlsCrypto.compute_verify_data(
            self.master_secret,
            self.handshake_messages,
            b"server finished"
        )
        
        finished_payload = Finished.pack(verify_data)
        
        # Wrap in handshake message
        handshake_msg = DtlsHandshakeMessage.pack(
            DtlsHandshakeType.FINISHED,
            self.handshake_seq,
            finished_payload
        )
        self.handshake_seq += 1
        
        # Wrap in DTLS record
        record = DtlsRecord.pack(
            DtlsContentType.HANDSHAKE,
            0,  # epoch 0 during handshake
            self.send_seq,
            handshake_msg
        )
        self.send_seq += 1
        
        # Mark session as established
        self.established = True
        self.epoch = 1
        self.send_seq = 0
        self.recv_seq = 0
        self.replay_window.reset()
        
        print(f"[DTLS-Server] Handshake complete with {self.node_nid.hex()[:8]}...")
        return record
    
    def _derive_keys(self):
        """Derive master secret and session keys via ECDH + HKDF"""
        print("[DTLS-Server] Deriving session keys...")
        
        # Perform ECDH
        shared_secret = self.ephemeral_private_key.exchange(
            ec.ECDH(), self.peer_ephemeral_public_key
        )
        
        # Derive master secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"dtls-master-secret",
            backend=default_backend()
        )
        self.master_secret = hkdf.derive(shared_secret)
        
        # Derive session keys
        (self.client_write_key, self.server_write_key,
         self.client_write_iv, self.server_write_iv) = DtlsCrypto.derive_keys(
            self.master_secret,
            self.client_random,
            self.server_random
        )
        
        print(f"[DTLS-Server] Keys derived: master_secret={self.master_secret[:8].hex()}...")
    
    def decrypt(self, dtls_record):
        """
        Decrypt DTLS record from client.
        
        Args:
            dtls_record: DTLS record bytes
            
        Returns:
            Decrypted application data
        """
        if not self.established:
            raise RuntimeError("DTLS session not established")
        
        # Unpack DTLS record
        content_type, epoch, seq_number, ciphertext_with_tag = DtlsRecord.unpack(dtls_record)
        
        if content_type != DtlsContentType.APPLICATION_DATA:
            raise ValueError(f"Expected APPLICATION_DATA, got {content_type}")
        
        if epoch != self.epoch:
            raise ValueError(f"Epoch mismatch: expected {self.epoch}, got {epoch}")
        
        # Anti-replay check
        if not self.replay_window.check_and_update(seq_number):
            raise ValueError(f"Replay detected: seq_number={seq_number}")
        
        # Reconstruct header for AAD
        header = DtlsRecord.pack_header(
            content_type,
            epoch,
            seq_number,
            len(ciphertext_with_tag)
        )
        
        # Decrypt with AES-GCM (client write keys - we're the server receiving from client)
        try:
            plaintext = DtlsCrypto.decrypt_record(
                ciphertext_with_tag,
                self.client_write_key,
                self.client_write_iv,
                epoch,
                seq_number,
                header  # AAD
            )
            return plaintext
        except InvalidTag:
            raise ValueError("DTLS record authentication failed")
    
    def encrypt(self, plaintext):
        """
        Encrypt application data to send to client.
        
        Args:
            plaintext: Application data to encrypt
            
        Returns:
            DTLS record bytes
        """
        if not self.established:
            raise RuntimeError("DTLS session not established")
        
        # Build DTLS record header
        header = DtlsRecord.pack_header(
            DtlsContentType.APPLICATION_DATA,
            self.epoch,
            self.send_seq,
            len(plaintext) + DtlsRecord.TAG_SIZE
        )
        
        # Encrypt with AES-GCM (server write keys)
        ciphertext_with_tag = DtlsCrypto.encrypt_record(
            plaintext,
            self.server_write_key,
            self.server_write_iv,
            self.epoch,
            self.send_seq,
            header  # AAD
        )
        
        # Increment sequence number
        self.send_seq += 1
        
        # Return complete DTLS record
        return header + ciphertext_with_tag

class DtlsServerManager:
    """
    Manages multiple DTLS sessions for the Sink.
    
    Tracks sessions by Node NID.
    """
    
    def __init__(self, sink_nid, cert_path, key_path, ca_cert_path):
        """
        Initialize DTLS server manager.
        
        Args:
            sink_nid: 16-byte Sink Network ID
            cert_path: Path to Sink certificate
            key_path: Path to Sink private key
            ca_cert_path: Path to CA certificate
        """
        self.sink_nid = sink_nid
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        # Map: node_nid -> DtlsServerSession
        self.sessions = {}
        
        print(f"[DTLS-Server] Manager initialized for Sink {sink_nid.hex()[:8]}...")
    
    def get_or_create_session(self, node_nid):
        """
        Get existing session or create new one for Node.
        
        Args:
            node_nid: 16-byte Node Network ID
            
        Returns:
            DtlsServerSession instance
        """
        if node_nid not in self.sessions:
            self.sessions[node_nid] = DtlsServerSession(
                node_nid,
                self.sink_nid,
                self.cert_path,
                self.key_path,
                self.ca_cert_path
            )
        return self.sessions[node_nid]
    
    def get_session(self, node_nid):
        """Get existing session for Node (or None)"""
        return self.sessions.get(node_nid)
    
    def remove_session(self, node_nid):
        """Remove session for Node"""
        if node_nid in self.sessions:
            del self.sessions[node_nid]
            print(f"[DTLS-Server] Session removed for {node_nid.hex()[:8]}...")
