"""
Node DTLS Client

Provides DTLS end-to-end encryption for Node-to-Sink communication.
Runs as a service alongside the Router.
"""

import threading
import time
from common.dtls_transport import DTLSTransport
from common.dtls_service import DTLSService


class NodeDTLSClient:
    """
    DTLS client service for Nodes.
    
    Establishes and maintains DTLS session with Sink for end-to-end encryption.
    """
    
    def __init__(self, router, cert_path: str, key_path: str, ca_cert_path: str, sink_nid: bytes):
        """
        Initialize Node DTLS client.
        
        Args:
            router: Router instance for transport
            cert_path: Path to Node's X.509 certificate
            key_path: Path to Node's private key
            ca_cert_path: Path to CA certificate
            sink_nid: Sink's Network ID
        """
        self.router = router
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        self.sink_nid = sink_nid
        
        self.transport = None
        self.dtls_service = None
        self.session_ready = False
        self.running = False
        
    def start(self):
        """
        Start DTLS client service.
        
        Establishes DTLS session with Sink in background thread.
        """
        self.running = True
        
        # Start session establishment in background
        session_thread = threading.Thread(target=self._establish_session_background, daemon=True)
        session_thread.start()
        
        print("[DTLS Client] Service started")
    
    def _establish_session_background(self):
        """Establish DTLS session in background thread."""
        # Wait for Router to be ready (have uplink)
        print("[DTLS Client] Waiting for network connectivity...")
        while self.running and not self.router.uplink_connection:
            time.sleep(1)
        
        if not self.running:
            return
        
        print("[DTLS Client] Network ready, establishing DTLS session...")
        
        try:
            # Create transport layer
            self.transport = DTLSTransport(self.router, self.sink_nid)
            
            # Create DTLS service (client mode)
            self.dtls_service = DTLSService(
                self.transport,
                self.cert_path,
                self.key_path,
                self.ca_cert_path,
                is_server=False
            )
            
            # Establish session
            self.dtls_service.establish_session()
            
            self.session_ready = True
            print("[DTLS Client] ✓ DTLS session established with Sink")
            
        except Exception as e:
            print(f"[DTLS Client] ✗ Failed to establish session: {e}")
            self.session_ready = False
    
    def send_to_sink(self, plaintext_data: bytes) -> bool:
        """
        Send encrypted data to Sink.
        
        Args:
            plaintext_data: Unencrypted data to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.session_ready:
            print("[DTLS Client] Session not ready")
            return False
        
        try:
            return self.dtls_service.send_secure(plaintext_data)
        except Exception as e:
            print(f"[DTLS Client] Send error: {e}")
            return False
    
    def receive_from_sink(self, timeout: float = None) -> bytes:
        """
        Receive and decrypt data from Sink.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            Exception: If receive fails
        """
        if not self.session_ready:
            raise Exception("DTLS session not ready")
        
        return self.dtls_service.receive_secure(timeout)
    
    def stop(self):
        """Stop DTLS client service."""
        self.running = False
        if self.dtls_service:
            self.dtls_service.close()
        print("[DTLS Client] Service stopped")
