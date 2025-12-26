"""
Sink DTLS Server

Implements DTLS-like server handshake and manages multiple encrypted sessions with Nodes.
"""

import os
import threading
import hmac
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from common.dtls_session import DTLSSession
from common.dtls_protocol import (
    ClientHello, ServerHello, Certificate, CertificateVerify, Finished,
    DTLSMessageType
)


class SinkDTLSTransport:
    """
    Special DTLS transport for Sink (doesn't use Router).
    Sends packets directly via SinkConnectionManager.
    """
    
    def __init__(self, conn_manager, node_nid: bytes):
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
        
        # Send via connection manager
        self.conn_manager.send_to_all_links(packet)
        return len(data)
    
    def recv(self, bufsize: int = 65535, timeout: float = None) -> bytes:
        """Receive DTLS data."""
        import queue
        try:
            data = self.recv_queue.get(timeout=timeout)
            return data
        except queue.Empty:
            raise TimeoutError("Receive timeout")
    
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
    
    def getpeername(self):
        return (self.node_nid.hex()[:15], 0)
    
    def getsockname(self):
        return (self.my_nid.hex()[:15], 0)
    
    def setsockopt(self, level, optname, value):
        pass
    
    def getsockopt(self, level, optname):
        return 0
    
    def fileno(self):
        raise NotImplementedError("Virtual DTLS transport doesn't have a file descriptor")


class SinkDTLSServer:
    """
    DTLS server for Sink.
    
    Manages multiple DTLS sessions with different Nodes.
    """
    
    def __init__(self, conn_manager, cert_path: str, key_path: str, ca_cert_path: str):
        self.conn_manager = conn_manager
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        # Map: Node NID -> DTLS session
        self.sessions: Dict[bytes, DTLSSession] = {}
        
        # Map: Node NID -> Transport
        self.transports: Dict[bytes, SinkDTLSTransport] = {}
        
        # Map: Node NID -> Handshake thread
        self.handshake_threads: Dict[bytes, threading.Thread] = {}
        
        self.running = False
        self.lock = threading.Lock()
    
    def start(self):
        """Start DTLS server."""
        self.running = True
        print("[DTLS Server] Service started")
    
    def handle_dtls_packet(self, src_nid: bytes, encrypted_data: bytes):
        """
        Handle incoming DTLS packet from a Node.
        
        Args:
            src_nid: Source Node's NID
            encrypted_data: DTLS data (handshake or application data)
        """
        with self.lock:
            # Check if we have a session with this Node
            if src_nid not in self.sessions:
                print(f"[DTLS Server] New DTLS connection from {src_nid.hex()[:8]}...")
                self._initiate_handshake(src_nid)
            
            # Deliver packet to transport
            if src_nid in self.transports:
                transport = self.transports[src_nid]
                transport._on_dtls_packet(src_nid, encrypted_data)
    
    def _initiate_handshake(self, node_nid: bytes):
        """
        Initiate DTLS handshake with a Node.
        
        Args:
            node_nid: Node's NID
        """
        # Create transport
        transport = SinkDTLSTransport(self.conn_manager, node_nid)
        self.transports[node_nid] = transport
        
        # Create session
        session = DTLSSession(
            transport,
            self.cert_path,
            self.key_path,
            self.ca_cert_path,
            is_server=True
        )
        self.sessions[node_nid] = session
        
        # Start handshake in background thread
        handshake_thread = threading.Thread(
            target=self._perform_handshake,
            args=(node_nid, session, transport),
            daemon=True
        )
        handshake_thread.start()
        self.handshake_threads[node_nid] = handshake_thread
    
    def _perform_handshake(self, node_nid: bytes, session: DTLSSession, transport: SinkDTLSTransport):
        """
        Perform DTLS-like server handshake.
        
        Flow:
        1. Receive ClientHello
        2. Send ServerHello
        3. Receive Certificate + CertificateVerify
        4. Send Finished
        5. Receive Finished
        """
        try:
            # Step 1: Receive ClientHello
            print(f"[DTLS Server] Waiting for ClientHello from {node_nid.hex()[:8]}...")
            client_hello_data = transport.recv(timeout=30.0)
            client_hello = ClientHello.unpack(client_hello_data)
            session.handshake_transcript += client_hello_data
            
            client_random = client_hello.client_random
            
            # Step 2: Generate ephemeral ECDH key pair
            ecdh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdh_public_key_bytes = ecdh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Step 3: Send ServerHello
            server_random = os.urandom(32)
            server_hello = ServerHello(
                server_random=server_random,
                server_nid=self.conn_manager.sink_nid,
                ecdh_public_key=ecdh_public_key_bytes,
                server_certificate=session.own_cert_der
            )
            
            print(f"[DTLS Server] Sending ServerHello to {node_nid.hex()[:8]}...")
            transport.send(server_hello.pack())
            session.handshake_transcript += server_hello.pack()
            
            # Step 4: Perform ECDH
            print(f"[DTLS Server] Performing ECDH...")
            session.ecdh_private_key = ecdh_private_key
            shared_secret = session._perform_ecdh(client_hello.ecdh_public_key)
            
            # Derive session keys
            print(f"[DTLS Server] Deriving session keys...")
            session._derive_keys(shared_secret, client_random, server_random)
            
            # Step 5: Receive Certificate from client
            print(f"[DTLS Server] Waiting for client Certificate...")
            cert_data = transport.recv(timeout=10.0)
            client_cert_msg = Certificate.unpack(cert_data)
            session.handshake_transcript += cert_data
            
            # Verify client certificate
            print(f"[DTLS Server] Verifying client certificate...")
            client_cert = session._verify_certificate(client_cert_msg.certificate)
            
            # Step 6: Receive CertificateVerify
            print(f"[DTLS Server] Waiting for CertificateVerify...")
            cert_verify_data = transport.recv(timeout=10.0)
            cert_verify = CertificateVerify.unpack(cert_verify_data)
            session.handshake_transcript += cert_verify_data
            
            # Verify signature
            transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            transcript_hash.update(session.handshake_transcript[:-len(cert_verify_data)])
            transcript_digest = transcript_hash.finalize()
            
            try:
                client_cert.public_key().verify(
                    cert_verify.signature,
                    transcript_digest,
                    ec.ECDSA(hashes.SHA256())
                )
                print(f"[DTLS Server] Client signature verified")
            except Exception as e:
                raise ValueError(f"Client signature verification failed: {e}")
            
            # Step 7: Send Finished
            print(f"[DTLS Server] Sending Finished...")
            server_verify = hmac.new(
                shared_secret,
                session.handshake_transcript,
                'sha256'
            ).digest()
            
            server_finished = Finished(verify_data=server_verify)
            transport.send(server_finished.pack())
            session.handshake_transcript += server_finished.pack()
            
            # Step 8: Receive client Finished
            print(f"[DTLS Server] Waiting for client Finished...")
            client_finished_data = transport.recv(timeout=10.0)
            client_finished = Finished.unpack(client_finished_data)
            
            # Verify client Finished
            expected_verify = hmac.new(
                shared_secret,
                session.handshake_transcript,
                'sha256'
            ).digest()
            
            if client_finished.verify_data != expected_verify:
                raise ValueError("Client Finished verification failed")
            
            # Mark session as established
            session.session_established = True
            print(f"[DTLS Server] ✓ Session established with {node_nid.hex()[:8]}...")
            
            # Start receiving application data
            self._receive_loop(node_nid, session)
            
        except Exception as e:
            print(f"[DTLS Server] ✗ Handshake failed with {node_nid.hex()[:8]}...: {e}")
            import traceback
            traceback.print_exc()
    
    def _receive_loop(self, node_nid: bytes, session: DTLSSession):
        """
        Receive and decrypt application data from Node.
        
        Args:
            node_nid: Node's NID
            session: Established DTLS session
        """
        while self.running and session.session_established:
            try:
                # Receive and decrypt
                plaintext = session.receive_secure(timeout=1.0)
                
                # Display message
                self._display_message(node_nid, plaintext)
                
            except TimeoutError:
                # No data, continue
                continue
            except Exception as e:
                print(f"[DTLS Server] Receive error from {node_nid.hex()[:8]}...: {e}")
                break
    
    def _display_message(self, src_nid: bytes, plaintext: bytes):
        """Display decrypted message from Node."""
        try:
            message_text = plaintext.decode('utf-8')
            separator = '=' * 60
            print(f"\n{separator}")
            print(f"🔓 DTLS INBOX MESSAGE")
            print(f"FROM: Node {src_nid.hex()}")
            print(f"TEXT: {message_text}")
            print(f"ENCRYPTED: Yes (DTLS end-to-end)")
            print(f"{separator}\n")
        except UnicodeDecodeError:
            print(f"[DTLS Server] Received binary data from {src_nid.hex()}: {plaintext.hex()}")
    
    def send_to_node(self, dest_nid: bytes, plaintext_data: bytes) -> bool:
        """Send encrypted data to a Node."""
        with self.lock:
            if dest_nid not in self.sessions:
                print(f"[DTLS Server] No session with {dest_nid.hex()[:8]}...")
                return False
            
            session = self.sessions[dest_nid]
            if not session.session_established:
                print(f"[DTLS Server] Session not established with {dest_nid.hex()[:8]}...")
                return False
            
            return session.send_secure(plaintext_data)
    
    def stop(self):
        """Stop DTLS server."""
        self.running = False
        with self.lock:
            for session in self.sessions.values():
                session.close()
        print("[DTLS Server] Service stopped")
