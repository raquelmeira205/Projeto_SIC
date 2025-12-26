"""
Node DTLS Client

Implements DTLS-like client handshake and encryption for Node-to-Sink communication.
"""

import os
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from common.dtls_transport import DTLSTransport
from common.dtls_session import DTLSSession
from common.dtls_protocol import (
    ClientHello, ServerHello, Certificate, CertificateVerify, Finished,
    DTLSMessageType
)


class NodeDTLSClient:
    """
    DTLS client for Nodes.
    
    Performs DTLS-like handshake with Sink and manages encrypted session.
    """
    
    def __init__(self, router, cert_path: str, key_path: str, ca_cert_path: str, sink_nid: bytes):
        """
        Initialize DTLS client.
        
        Args:
            router: Router instance
            cert_path: Path to Node's certificate
            key_path: Path to Node's private key
            ca_cert_path: Path to CA certificate
            sink_nid: Sink's NID (all zeros)
        """
        self.router = router
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        self.sink_nid = sink_nid
        
        self.transport = None
        self.session = None
        self.running = False
        
        # Handshake state
        self.client_random = None
        self.server_random = None
        self.ecdh_private_key = None
        self.ecdh_public_key_bytes = None
    
    def start(self):
        """Start DTLS client and initiate handshake."""
        self.running = True
        
        # Start handshake in background
        handshake_thread = threading.Thread(target=self._handshake_background, daemon=True)
        handshake_thread.start()
        
        print("[DTLS Client] Service started")
    
    def _handshake_background(self):
        """Perform handshake in background thread."""
        # Wait for Router to be ready
        print("[DTLS Client] Waiting for network connectivity...")
        while self.running and not self.router.uplink_connection:
            time.sleep(1)
        
        if not self.running:
            return
        
        # Wait for hop-by-hop session key to be established
        print("[DTLS Client] Waiting for hop-by-hop handshake...")
        while self.running:
            uplink_mac = self.router.uplink_connection
            if uplink_mac and uplink_mac in self.router.link_keys:
                break
            time.sleep(0.5)
        
        if not self.running:
            return
        
        print("[DTLS Client] Network ready, starting DTLS handshake...")
        
        try:
            # Create transport
            self.transport = DTLSTransport(self.router, self.sink_nid)
            
            # Create session
            self.session = DTLSSession(
                self.transport,
                self.cert_path,
                self.key_path,
                self.ca_cert_path,
                is_server=False
            )
            
            # Perform handshake
            self._perform_handshake()
            
            print("[DTLS Client] ✓ Handshake complete, session established")
            
        except Exception as e:
            print(f"[DTLS Client] ✗ Handshake failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _perform_handshake(self):
        """
        Perform DTLS-like handshake.
        
        Flow:
        1. Send ClientHello
        2. Receive ServerHello
        3. Send Certificate + CertificateVerify
        4. Receive Finished
        5. Send Finished
        """
        # Step 1: Generate ephemeral ECDH key pair
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ecdh_public_key_bytes = self.ecdh_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Step 2: Send ClientHello
        self.client_random = os.urandom(32)
        client_hello = ClientHello(
            client_random=self.client_random,
            client_nid=self.router.my_nid,
            ecdh_public_key=self.ecdh_public_key_bytes
        )
        
        print("[DTLS Client] Sending ClientHello...")
        self.transport.send(client_hello.pack())
        self.session.handshake_transcript += client_hello.pack()
        
        # Step 3: Receive ServerHello
        print("[DTLS Client] Waiting for ServerHello...")
        server_hello_data = self.transport.recv(timeout=10.0)
        server_hello = ServerHello.unpack(server_hello_data)
        self.session.handshake_transcript += server_hello_data
        
        self.server_random = server_hello.server_random
        
        # Verify server certificate
        print("[DTLS Client] Verifying server certificate...")
        server_cert = self.session._verify_certificate(server_hello.server_certificate)
        
        # Perform ECDH
        print("[DTLS Client] Performing ECDH key exchange...")
        self.session.ecdh_private_key = self.ecdh_private_key
        shared_secret = self.session._perform_ecdh(server_hello.ecdh_public_key)
        
        # Derive session keys
        print("[DTLS Client] Deriving session keys...")
        self.session._derive_keys(shared_secret, self.client_random, self.server_random)
        
        # Step 4: Send Certificate
        print("[DTLS Client] Sending Certificate...")
        cert_msg = Certificate(certificate=self.session.own_cert_der)
        self.transport.send(cert_msg.pack())
        self.session.handshake_transcript += cert_msg.pack()
        
        # Step 5: Send CertificateVerify (signature over transcript)
        print("[DTLS Client] Sending CertificateVerify...")
        transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        transcript_hash.update(self.session.handshake_transcript)
        transcript_digest = transcript_hash.finalize()
        
        signature = self.session.own_private_key.sign(
            transcript_digest,
            ec.ECDSA(hashes.SHA256())
        )
        
        cert_verify = CertificateVerify(signature=signature)
        self.transport.send(cert_verify.pack())
        self.session.handshake_transcript += cert_verify.pack()
        
        # Step 6: Receive Finished from server
        print("[DTLS Client] Waiting for server Finished...")
        finished_data = self.transport.recv(timeout=10.0)
        server_finished = Finished.unpack(finished_data)
        
        # Verify server's Finished message
        import hmac
        expected_verify = hmac.new(
            shared_secret,
            self.session.handshake_transcript,
            'sha256'
        ).digest()
        
        if server_finished.verify_data != expected_verify:
            raise ValueError("Server Finished verification failed")
        
        # Step 7: Send our Finished
        print("[DTLS Client] Sending Finished...")
        self.session.handshake_transcript += finished_data
        
        client_verify = hmac.new(
            shared_secret,
            self.session.handshake_transcript,
            'sha256'
        ).digest()
        
        client_finished = Finished(verify_data=client_verify)
        self.transport.send(client_finished.pack())
        
        # Mark session as established
        self.session.session_established = True
        print("[DTLS Client] Session established!")
    
    def send_to_sink(self, plaintext_data: bytes) -> bool:
        """
        Send encrypted data to Sink.
        
        Args:
            plaintext_data: Data to send
            
        Returns:
            True if successful
        """
        if not self.session or not self.session.session_established:
            print("[DTLS Client] Session not ready")
            return False
        
        return self.session.send_secure(plaintext_data)
    
    def receive_from_sink(self, timeout: float = None) -> bytes:
        """
        Receive encrypted data from Sink.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Decrypted data
        """
        if not self.session or not self.session.session_established:
            raise RuntimeError("Session not ready")
        
        return self.session.receive_secure(timeout)
    
    def stop(self):
        """Stop DTLS client."""
        self.running = False
        if self.session:
            self.session.close()
        print("[DTLS Client] Stopped")
