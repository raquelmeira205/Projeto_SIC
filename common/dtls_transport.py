"""
DTLS Transport Layer

Provides a virtual UDP socket interface that uses the Router as transport.
This allows DTLS to run on top of the existing multi-hop routing infrastructure.
"""

import threading
import queue
import time
from typing import Callable, Optional


class DTLSTransport:
    """
    Virtual UDP socket that uses Router for transport.
    
    Provides socket-like send/recv interface for DTLS library.
    """
    
    def __init__(self, router, dest_nid: bytes):
        """
        Initialize DTLS transport.
        
        Args:
            router: Router instance to use for sending/receiving
            dest_nid: Destination NID (Sink's NID for Nodes, Node's NID for Sink)
        """
        self.router = router
        self.dest_nid = dest_nid
        self.my_nid = router.my_nid
        
        # Queue for incoming DTLS packets
        self.recv_queue = queue.Queue()
        
        # Register callback with router
        self.router.register_dtls_callback(self._on_dtls_packet)
        
        # Socket state
        self.connected = False
        self.peer_addr = None  # For compatibility with socket API
        
    def _on_dtls_packet(self, src_nid: bytes, payload: bytes):
        """
        Callback for when Router receives a DTLS packet.
        
        Args:
            src_nid: Source NID of the packet
            payload: DTLS encrypted payload
        """
        # Only accept packets from our peer
        if src_nid == self.dest_nid:
            self.recv_queue.put(payload)
    
    def send(self, data: bytes) -> int:
        """
        Send data via Router to destination.
        
        Args:
            data: DTLS encrypted data to send
            
        Returns:
            Number of bytes sent
        """
        from common.packet_structs import MsgType
        
        # Use Router to send DTLS packet
        success = self.router.send_dtls_data(self.dest_nid, data)
        
        if success:
            return len(data)
        else:
            raise IOError("Failed to send DTLS packet via Router")
    
    def recv(self, bufsize: int = 65535, timeout: Optional[float] = None) -> bytes:
        """
        Receive data from Router queue.
        
        Args:
            bufsize: Maximum bytes to receive (for compatibility)
            timeout: Timeout in seconds (None = block forever)
            
        Returns:
            Received DTLS data
            
        Raises:
            TimeoutError: If timeout expires
        """
        try:
            data = self.recv_queue.get(timeout=timeout)
            return data
        except queue.Empty:
            raise TimeoutError("Receive timeout")
    
    def sendto(self, data: bytes, address) -> int:
        """
        Socket-compatible sendto (ignores address, uses dest_nid).
        
        Args:
            data: Data to send
            address: Ignored (for socket API compatibility)
            
        Returns:
            Number of bytes sent
        """
        return self.send(data)
    
    def recvfrom(self, bufsize: int = 65535) -> tuple:
        """
        Socket-compatible recvfrom.
        
        Args:
            bufsize: Maximum bytes to receive
            
        Returns:
            Tuple of (data, address) where address is dest_nid
        """
        data = self.recv(bufsize)
        return (data, self.dest_nid)
    
    def connect(self, address):
        """
        Socket-compatible connect (for DTLS library).
        
        Args:
            address: Ignored (we already know dest_nid)
        """
        self.connected = True
        self.peer_addr = address
    
    def close(self):
        """Close the transport (cleanup)."""
        self.connected = False
        # Unregister callback if needed
        # (Router doesn't have unregister yet, but could add)
    
    def settimeout(self, timeout: Optional[float]):
        """
        Set default timeout for recv operations.
        
        Args:
            timeout: Timeout in seconds (None = blocking)
        """
        # Store for use in recv()
        self.default_timeout = timeout
    
    def gettimeout(self) -> Optional[float]:
        """Get current timeout setting."""
        return getattr(self, 'default_timeout', None)
    
    def fileno(self):
        """
        Return file descriptor (not supported for virtual socket).
        
        Raises:
            NotImplementedError: Virtual sockets don't have file descriptors
        """
        raise NotImplementedError("Virtual DTLS transport doesn't have a file descriptor")
