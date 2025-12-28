"""
DTLS-like client session for end-to-end security.

This module implements a DTLS-like session that provides end-to-end
encryption and authentication between IoT Nodes and the Sink.

The DTLS session sits above the Router layer, encrypting application
data before it's sent through the multi-hop network.
"""

import secrets
import time
from enum import Enum
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
from common.packet_structs import MsgType

class DtlsState(Enum):
    """DTLS session states"""
    IDLE = "IDLE"
    HANDSHAKING = "HANDSHAKING"
    ESTABLISHED = "ESTABLISHED"
    CLOSED = "CLOSED"

class DtlsSession:
    """
    DTLS-like session for end-to-end security.
    
    Provides:
    - Mutual authentication using X.509 certificates
    - Key agreement via ECDH
    - AES-GCM encryption for application data
    - Anti-replay protection with sliding window
    """
    
    def __init__(self, sink_nid, my_nid, cert_path, key_path, ca_cert_path, router):
        """
        Initialize DTLS session.
        
        Args:
            sink_nid: 16-byte Sink Network ID
            my_nid: 16-byte my Network ID
            cert_path: Path to my certificate
            key_path: Path to my private key
            ca_cert_path: Path to CA certificate
            router: Router instance for sending handshake messages
        """
        self.sink_nid = sink_nid
        self.my_nid = my_nid
        self.router = router
        
        # Load certificates and keys
        self.cert = self._load_cert(cert_path)
        self.private_key = self._load_key(key_path)
        self.ca_cert = self._load_cert(ca_cert_path)
        
        # Session state
        self.state = DtlsState.IDLE
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
        self.handshake_messages = b''  # Transcript for Finished message
        self.handshake_seq = 0
        
        # Derived keys (after handshake)
        self.master_secret = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None
        
        # Pending handshake response
        self.pending_response = None
        self.handshake_timeout = 10.0
        
        print(f"[DTLS] Session initialized for Sink {sink_nid.hex()[:8]}...")
    
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
            print(f"[DTLS] Certificate verification failed: {e}")
            return False
    
    def perform_handshake(self):
        """
        Perform DTLS handshake with Sink.
        
        Handshake flow:
        1. Node → Sink: ClientHello (random, NID, ECDH public key)
        2. Sink → Node: ServerHello (random, NID, ECDH public key, certificate)
        3. Node → Sink: ClientKeyExchange (certificate, signature)
        4. Sink → Node: Finished (verify_data)
        5. Both derive keys and establish session
        """
        print("[DTLS] Starting handshake with Sink...")
        self.state = DtlsState.HANDSHAKING
        
        # Generate ephemeral ECDH key pair
        self.ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ephemeral_public_key = self.ephemeral_private_key.public_key()
        
        # Generate client random
        self.client_random = secrets.token_bytes(32)
        
        # Serialize ECDH public key
        ecdh_public_pem = self.ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Build ClientHello
        client_hello_payload = ClientHello.pack(
            self.client_random,
            self.my_nid,
            ecdh_public_pem
        )
        
        # Wrap in handshake message
        handshake_msg = DtlsHandshakeMessage.pack(
            DtlsHandshakeType.CLIENT_HELLO,
            self.handshake_seq,
            client_hello_payload
        )
        self.handshake_seq += 1
        
        # Add to transcript
        self.handshake_messages += handshake_msg
        
        # Send via Router as DTLS_HANDSHAKE message
        print("[DTLS] Sending ClientHello...")
        self._send_handshake_message(handshake_msg)
        
        # Wait for ServerHello
        if not self._wait_for_response():
            raise RuntimeError("Handshake timeout waiting for ServerHello")
        
        # Process ServerHello
        self._process_server_hello(self.pending_response)
        self.pending_response = None
        
        # Send ClientKeyExchange
        self._send_client_key_exchange()
        
        # Wait for Finished
        if not self._wait_for_response():
            raise RuntimeError("Handshake timeout waiting for Finished")
        
        # Process Finished
        self._process_finished(self.pending_response)
        self.pending_response = None
        
        # Handshake complete
        self.state = DtlsState.ESTABLISHED
        print(f"[DTLS] Handshake complete! Session established with epoch {self.epoch}")
    
    def _send_handshake_message(self, handshake_msg):
        """Send handshake message via Router"""
        # Wrap in DTLS record (epoch 0 during handshake)
        record = DtlsRecord.pack(
            DtlsContentType.HANDSHAKE,
            0,  # epoch 0 during handshake
            self.send_seq,
            handshake_msg
        )
        self.send_seq += 1
        
        # Send via Router with DTLS_HANDSHAKE message type
        # Router will apply hop-by-hop MAC
        self.router._route_data(self.my_nid, self.sink_nid, record, MsgType.DTLS_HANDSHAKE)
    
    def _wait_for_response(self):
        """Wait for handshake response"""
        start_time = time.time()
        while time.time() - start_time < self.handshake_timeout:
            if self.pending_response is not None:
                return True
            time.sleep(0.1)
        return False
    
    def handle_handshake_message(self, dtls_record):
        """
        Handle incoming DTLS handshake message.
        
        Called by Router when DTLS_HANDSHAKE message is received.
        """
        try:
            # Unpack DTLS record
            content_type, epoch, seq_number, payload = DtlsRecord.unpack(dtls_record)
            
            if content_type != DtlsContentType.HANDSHAKE:
                print(f"[DTLS] Unexpected content type: {content_type}")
                return
            
            # Store for processing
            self.pending_response = payload
            
        except Exception as e:
            print(f"[DTLS] Error handling handshake message: {e}")
    
    def _process_server_hello(self, handshake_msg):
        """Process ServerHello message"""
        print("[DTLS] Processing ServerHello...")
        
        # Add to transcript
        self.handshake_messages += handshake_msg
        
        # Unpack handshake message
        msg_type, msg_seq, fragment = DtlsHandshakeMessage.unpack(handshake_msg)
        
        if msg_type != DtlsHandshakeType.SERVER_HELLO:
            raise ValueError(f"Expected SERVER_HELLO, got {msg_type}")
        
        # Unpack ServerHello
        server_random, server_nid, ecdh_public_pem, cert_pem = ServerHello.unpack(fragment)
        
        # Verify server NID matches Sink
        if server_nid != self.sink_nid:
            raise ValueError("Server NID mismatch")
        
        self.server_random = server_random
        
        # Load and verify server certificate
        self.peer_cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        if not self._verify_certificate(self.peer_cert):
            raise ValueError("Server certificate verification failed")
        
        # Load server ECDH public key
        self.peer_ephemeral_public_key = serialization.load_pem_public_key(
            ecdh_public_pem, default_backend()
        )
        
        print("[DTLS] ServerHello processed successfully")
    
    def _send_client_key_exchange(self):
        """Send ClientKeyExchange with certificate and signature"""
        print("[DTLS] Sending ClientKeyExchange...")
        
        # Serialize my certificate
        cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        
        # Sign handshake transcript with my private key
        signature = self.private_key.sign(
            self.handshake_messages,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Build ClientKeyExchange
        client_key_exchange_payload = ClientKeyExchange.pack(cert_pem, signature)
        
        # Wrap in handshake message
        handshake_msg = DtlsHandshakeMessage.pack(
            DtlsHandshakeType.CLIENT_KEY_EXCHANGE,
            self.handshake_seq,
            client_key_exchange_payload
        )
        self.handshake_seq += 1
        
        # Add to transcript
        self.handshake_messages += handshake_msg
        
        # Derive master secret now (we have both ECDH keys)
        self._derive_keys()
        
        # Send message
        self._send_handshake_message(handshake_msg)
    
    def _derive_keys(self):
        """Derive master secret and session keys via ECDH + HKDF"""
        print("[DTLS] Deriving session keys...")
        
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
        
        print(f"[DTLS] Keys derived: master_secret={self.master_secret[:8].hex()}...")
    
    def _process_finished(self, handshake_msg):
        """Process Finished message from server"""
        print("[DTLS] Processing Finished...")
        
        # Unpack handshake message
        msg_type, msg_seq, fragment = DtlsHandshakeMessage.unpack(handshake_msg)
        
        if msg_type != DtlsHandshakeType.FINISHED:
            raise ValueError(f"Expected FINISHED, got {msg_type}")
        
        # Unpack Finished
        verify_data = Finished.unpack(fragment)
        
        # Compute expected verify_data
        expected_verify_data = DtlsCrypto.compute_verify_data(
            self.master_secret,
            self.handshake_messages,
            b"server finished"
        )
        
        # Verify
        if verify_data != expected_verify_data:
            raise ValueError("Finished verify_data mismatch")
        
        # Increment epoch (handshake complete, now use epoch 1 for application data)
        self.epoch = 1
        self.send_seq = 0
        self.recv_seq = 0
        self.replay_window.reset()
        
        print("[DTLS] Finished verified successfully")
    
    def send(self, plaintext):
        """
        Encrypt application data and return DTLS record.
        
        Args:
            plaintext: Application data to encrypt
            
        Returns:
            DTLS record bytes (to be sent via Router)
        """
        if self.state != DtlsState.ESTABLISHED:
            raise RuntimeError("DTLS session not established")
        
        # Build DTLS record header
        header = DtlsRecord.pack_header(
            DtlsContentType.APPLICATION_DATA,
            self.epoch,
            self.send_seq,
            len(plaintext) + DtlsRecord.TAG_SIZE  # ciphertext + tag
        )
        
        # Encrypt with AES-GCM (client write keys)
        ciphertext_with_tag = DtlsCrypto.encrypt_record(
            plaintext,
            self.client_write_key,
            self.client_write_iv,
            self.epoch,
            self.send_seq,
            header  # AAD
        )
        
        # Increment sequence number
        self.send_seq += 1
        
        # Return complete DTLS record
        return header + ciphertext_with_tag
    
    def recv(self, dtls_record):
        """
        Decrypt DTLS record and return application data.
        
        Args:
            dtls_record: DTLS record bytes
            
        Returns:
            Decrypted application data
        """
        if self.state != DtlsState.ESTABLISHED:
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
        
        # Decrypt with AES-GCM (server write keys - we're the client receiving from server)
        try:
            plaintext = DtlsCrypto.decrypt_record(
                ciphertext_with_tag,
                self.server_write_key,
                self.server_write_iv,
                epoch,
                seq_number,
                header  # AAD
            )
            return plaintext
        except InvalidTag:
            raise ValueError("DTLS record authentication failed")
    
    def close(self):
        """Close DTLS session"""
        self.state = DtlsState.CLOSED
        print("[DTLS] Session closed")
