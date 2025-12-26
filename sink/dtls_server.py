"""
Sink DTLS Server

Provides DTLS end-to-end decryption for Node-to-Sink communication.
Handles multiple DTLS sessions (one per Node).
"""

import threading
from typing import Dict
from common.dtls_transport import DTLSTransport
from common.dtls_service import DTLSService


class SinkDTLSServer:
    """
    DTLS server service for Sink.
    
    Manages multiple DTLS sessions with different Nodes.
    """
    
    def __init__(self, conn_manager, cert_path: str, key_path: str, ca_cert_path: str):
        """
        Initialize Sink DTLS server.
        
        Args:
            conn_manager: SinkConnectionManager instance
            cert_path: Path to Sink's X.509 certificate
            key_path: Path to Sink's private key
            ca_cert_path: Path to CA certificate
        """
        self.conn_manager = conn_manager
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        # Map: Node NID -> DTLS session
        self.dtls_sessions: Dict[bytes, DTLSService] = {}
        
        # Map: Node NID -> DTLSTransport
        self.transports: Dict[bytes, DTLSTransport] = {}
        
        self.running = False
        self.lock = threading.Lock()
        
    def start(self):
        """Start DTLS server service."""
        self.running = True
        print("[DTLS Server] Service started")
    
    def handle_dtls_packet(self, src_nid: bytes, encrypted_data: bytes):
        """
        Handle incoming DTLS packet from a Node.
        
        Args:
            src_nid: Source Node's NID
            encrypted_data: DTLS encrypted payload
        """
        with self.lock:
            # Check if we have a session with this Node
            if src_nid not in self.dtls_sessions:
                print(f"[DTLS Server] New DTLS connection from {src_nid.hex()[:8]}...")
                self._establish_session_with_node(src_nid)
            
            # Get the transport and deliver the packet
            if src_nid in self.transports:
                transport = self.transports[src_nid]
                # Deliver to transport's receive queue
                transport._on_dtls_packet(src_nid, encrypted_data)
                
                # Try to receive and decrypt
                try:
                    dtls_service = self.dtls_sessions[src_nid]
                    plaintext = dtls_service.receive_secure(timeout=0.1)
                    
                    # Display decrypted message
                    self._display_message(src_nid, plaintext)
                    
                except Exception as e:
                    # Timeout or other error - packet might be part of handshake
                    pass
    
    def _establish_session_with_node(self, node_nid: bytes):
        """
        Establish DTLS session with a Node.
        
        Args:
            node_nid: Node's NID
        """
        try:
            # Create a virtual transport for this Node
            # We need a special transport that doesn't use Router (Sink doesn't have Router)
            transport = SinkDTLSTransport(self.conn_manager, node_nid)
            self.transports[node_nid] = transport
            
            # Create DTLS service in server mode
            dtls_service = DTLSService(
                transport,
                self.cert_path,
                self.key_path,
                self.ca_cert_path,
                is_server=True
            )
            
            # Establish session (will complete when Node sends handshake)
            dtls_service.establish_session()
            
            self.dtls_sessions[node_nid] = dtls_service
            print(f"[DTLS Server] ✓ Session established with {node_nid.hex()[:8]}...")
            
        except Exception as e:
            print(f"[DTLS Server] ✗ Failed to establish session with {node_nid.hex()[:8]}...: {e}")
    
    def _display_message(self, src_nid: bytes, plaintext: bytes):
        """
        Display decrypted message from Node.
        
        Args:
            src_nid: Source Node's NID
            plaintext: Decrypted message
        """
        try:
            message_text = plaintext.decode('utf-8')
            print(f\"\\n{'='*60}\")
            print(f\"🔓 DTLS INBOX MESSAGE\")
            print(f\"FROM: Node {src_nid.hex()}\")
            print(f\"TEXT: {message_text}\")
            print(f\"ENCRYPTED: Yes (DTLS end-to-end)\")
            print(f\"{'='*60}\\n\")
        except UnicodeDecodeError:
            print(f\"[DTLS Server] Received binary data from {src_nid.hex()}: {plaintext.hex()}\")
    
    def send_to_node(self, dest_nid: bytes, plaintext_data: bytes) -> bool:
        """
        Send encrypted data to a Node.
        
        Args:
            dest_nid: Destination Node's NID
            plaintext_data: Unencrypted data to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        with self.lock:
            if dest_nid not in self.dtls_sessions:
                print(f\"[DTLS Server] No session with {dest_nid.hex()[:8]}...\")
                return False
            
            try:
                dtls_service = self.dtls_sessions[dest_nid]
                return dtls_service.send_secure(plaintext_data)
            except Exception as e:
                print(f\"[DTLS Server] Send error: {e}\")
                return False
    
    def stop(self):
        """Stop DTLS server service."""
        self.running = False
        with self.lock:
            for dtls_service in self.dtls_sessions.values():
                dtls_service.close()
        print(\"[DTLS Server] Service stopped\")


class SinkDTLSTransport:
    """
    Special DTLS transport for Sink (doesn't use Router).
    
    Sends packets directly via SinkConnectionManager.
    """
    
    def __init__(self, conn_manager, node_nid: bytes):
        """
        Initialize Sink DTLS transport.
        
        Args:
            conn_manager: SinkConnectionManager instance
            node_nid: Node's NID
        """
        self.conn_manager = conn_manager
        self.node_nid = node_nid
        self.my_nid = conn_manager.sink_nid
        
        import queue
        self.recv_queue = queue.Queue()
    
    def _on_dtls_packet(self, src_nid: bytes, payload: bytes):
        """Callback for incoming DTLS packet."""
        if src_nid == self.node_nid:
            self.recv_queue.put(payload)
    
    def send(self, data: bytes) -> int:
        """Send DTLS data to Node."""
        from common.packet_structs import PacketHeader, MsgType
        
        # Create DTLS packet
        packet = PacketHeader.pack(
            self.my_nid,
            self.node_nid,
            MsgType.DTLS_DATA,
            data
        )
        
        # Send via connection manager (will add link-layer MAC)
        # TODO: Need to implement send_dtls_packet in SinkConnectionManager
        # For now, use send_to_all_links (not ideal but works for single node)
        self.conn_manager.send_to_all_links(packet)
        
        return len(data)
    
    def recv(self, bufsize: int = 65535, timeout: float = None) -> bytes:
        """Receive DTLS data."""
        import queue
        try:
            data = self.recv_queue.get(timeout=timeout)
            return data
        except queue.Empty:
            raise TimeoutError(\"Receive timeout\")
    
    def sendto(self, data: bytes, address) -> int:
        return self.send(data)
    
    def recvfrom(self, bufsize: int = 65535) -> tuple:
        data = self.recv(bufsize)
        return (data, self.node_nid)
    
    def connect(self, address):
        pass
    
    def close(self):
        pass
    
    def settimeout(self, timeout: float):
        self.default_timeout = timeout
    
    def gettimeout(self) -> float:
        return getattr(self, 'default_timeout', None)
    
    def fileno(self):
        raise NotImplementedError(\"Virtual DTLS transport doesn't have a file descriptor\")
