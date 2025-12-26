"""
DTLS Service

Manages DTLS sessions for end-to-end encryption between Nodes and Sink.
Uses the python3-dtls library with certificate-based mutual authentication.
"""

import socket
import ssl
from dtls.wrapper import wrap_client, wrap_server
import threading
import time


class DTLSService:
    """
    DTLS session management for end-to-end encryption.
    
    Provides encrypt/decrypt and send/receive methods for secure communication.
    """
    
    def __init__(self, transport, cert_path: str, key_path: str, ca_cert_path: str, 
                 is_server: bool = False):
        """
        Initialize DTLS service.
        
        Args:
            transport: DTLSTransport instance (virtual UDP socket)
            cert_path: Path to X.509 certificate
            key_path: Path to private key
            ca_cert_path: Path to CA certificate for verification
            is_server: True for Sink (server mode), False for Node (client mode)
        """
        self.transport = transport
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        self.is_server = is_server
        
        self.dtls_session = None
        self.session_established = False
        self.lock = threading.Lock()
        
    def establish_session(self):
        """
        Establish DTLS session with peer.
        
        For Nodes: Initiates connection to Sink
        For Sink: Accepts connection from Node
        
        Raises:
            Exception: If DTLS handshake fails
        """
        print(f"[DTLS] Establishing session ({'server' if self.is_server else 'client'} mode)...")
        
        try:
            if self.is_server:
                self._establish_server_session()
            else:
                self._establish_client_session()
            
            self.session_established = True
            print(f"[DTLS] ✓ Session established successfully")
            
        except Exception as e:
            print(f"[DTLS] ✗ Failed to establish session: {e}")
            raise
    
    def _establish_client_session(self):
        """Establish DTLS session as client (Node side)."""
        # Create DTLS connection in client mode using python3-dtls
        print("[DTLS] Performing client handshake...")
        
        self.dtls_session = wrap_client(
            self.transport,
            keyfile=self.key_path,
            certfile=self.cert_path,
            ca_certs=self.ca_cert_path,
            cert_reqs=ssl.CERT_REQUIRED,
            do_handshake_on_connect=True
        )
        
        print("[DTLS] Client handshake complete")

    
    def _establish_server_session(self):
        """Establish DTLS session as server (Sink side)."""
        # Create DTLS connection in server mode using python3-dtls
        print("[DTLS] Performing server handshake...")
        
        self.dtls_session = wrap_server(
            self.transport,
            keyfile=self.key_path,
            certfile=self.cert_path,
            ca_certs=self.ca_cert_path,
            cert_reqs=ssl.CERT_REQUIRED,
            do_handshake_on_connect=True
        )
        
        print("[DTLS] Server handshake complete")
    
    def send_secure(self, plaintext_data: bytes) -> bool:
        """
        Encrypt and send data via DTLS.
        
        Args:
            plaintext_data: Unencrypted data to send
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session_established:
            print("[DTLS] Error: Session not established")
            return False
        
        try:
            with self.lock:
                self.dtls_session.send(plaintext_data)
            return True
        except Exception as e:
            print(f"[DTLS] Send error: {e}")
            return False
    
    def receive_secure(self, timeout: float = None) -> bytes:
        """
        Receive and decrypt data via DTLS.
        
        Args:
            timeout: Timeout in seconds (None = block forever)
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            TimeoutError: If timeout expires
            Exception: If receive fails
        """
        if not self.session_established:
            raise Exception("DTLS session not established")
        
        try:
            # Set timeout on transport if provided
            if timeout is not None:
                self.transport.settimeout(timeout)
            
            with self.lock:
                data = self.dtls_session.recv(4096)
            
            return data
        except Exception as e:
            print(f"[DTLS] Receive error: {e}")
            raise
    
    def close(self):
        """Close DTLS session."""
        if self.dtls_session:
            try:
                self.dtls_session.shutdown(socket.SHUT_RDWR)
                self.dtls_session.close()
            except:
                pass
        self.session_established = False
        print("[DTLS] Session closed")
