"""
BLE Transport Adapter for Security Handshake

This module provides a transport layer that adapts BLE GATT characteristic
read/write operations to work with the SecurityHandshake protocol.
"""

import time
from gi.repository import GLib
from common.ble_utils import get_gatt_characteristic, SIC_RX_CHAR_UUID


class BLEHandshakeTransport:
    """
    Transport adapter for performing security handshake over BLE GATT.
    
    This class wraps BLE GATT characteristic operations to provide
    send() and receive() methods required by SecurityHandshake.
    """
    
    def __init__(self, mac_address, ble_manager, is_initiator=True, timeout=10.0):
        """
        Initialize BLE handshake transport.
        
        Args:
            mac_address: MAC address of the peer device
            ble_manager: BLEManager instance for sending packets
            is_initiator: True if this side initiates the handshake
            timeout: Timeout in seconds for receive operations
        """
        self.mac = mac_address
        self.ble_manager = ble_manager
        self.is_initiator = is_initiator
        self.timeout = timeout
        self.receive_buffer = []
        self.receive_complete = False
        
    def send(self, data):
        """
        Send data over BLE using the BLE manager's send_packet method.
        
        Args:
            data: bytes to send
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        # BLE GATT has MTU limitations (typically 512 bytes max)
        # For handshake, we need to send certificates and keys which can be large
        # We'll chunk the data with a simple framing protocol:
        # [0xFF (handshake marker)][total_length (4 bytes)][chunk_index (2 bytes)][chunk_data]
        
        MAX_CHUNK_SIZE = 480  # Conservative chunk size to leave room for framing
        total_length = len(data)
        num_chunks = (total_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        
        print(f"[Handshake-TX] Sending {total_length} bytes in {num_chunks} chunks to {self.mac}")
        
        for i in range(num_chunks):
            start = i * MAX_CHUNK_SIZE
            end = min(start + MAX_CHUNK_SIZE, total_length)
            chunk_data = data[start:end]
            
            # Frame: [0xFF marker][total_length][chunk_index][chunk_data]
            frame = (
                b'\xFF' +  # Handshake marker to distinguish from regular packets
                total_length.to_bytes(4, 'big') +
                i.to_bytes(2, 'big') +
                chunk_data
            )
            
            # Use BLE manager to send the packet
            success = self.ble_manager.send_packet(self.mac, frame)
            if not success:
                raise RuntimeError(f"Failed to send chunk {i}/{num_chunks}")
            
            time.sleep(0.05)  # Small delay between chunks
        
        print(f"[Handshake-TX] Sent {num_chunks} chunks successfully")
    
    def receive(self):
        """
        Receive data over BLE GATT characteristic.
        
        This is a blocking call that waits for data to arrive.
        In a real implementation, this would use callbacks or async I/O.
        
        For now, we'll use a simple polling mechanism with the receive buffer
        that gets populated by the RxCharacteristic.WriteValue callback.
        
        Returns:
            bytes: received data
        """
        print(f"[Handshake-RX] Waiting to receive data from {self.mac}")
        
        expected_length = None
        
        # In the actual implementation, the RxCharacteristic will populate
        # a receive queue that we poll here. For now, we'll implement a 
        # simplified version that expects the router to call set_received_data()
        
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            if self.receive_buffer:
                # Get expected length from first chunk
                if expected_length is None and self.receive_buffer:
                    expected_length = self.receive_buffer[0][0]
                    print(f"[Handshake-RX-DEBUG] Expecting message of {expected_length} bytes")
                
                # Filter out chunks that don't match this message
                matching_chunks = [c for c in self.receive_buffer if c[0] == expected_length]
                
                # Reassemble chunks for this message only
                data = self._reassemble_chunks_filtered(matching_chunks, expected_length)
                if data is not None:
                    print(f"[Handshake-RX] Received {len(data)} bytes")
                    # Remove only the matching chunks, keep others for next receive()
                    self.receive_buffer = [c for c in self.receive_buffer if c[0] != expected_length]
                    return data
            time.sleep(0.1)
        
        raise TimeoutError(f"Timeout waiting for data from {self.mac}")
    
    def _reassemble_chunks_filtered(self, chunks, expected_length):
        """
        Reassemble chunks for a specific message length.
        
        Args:
            chunks: List of chunks with matching total_length
            expected_length: The expected total length
            
        Returns:
            bytes if complete message received, None otherwise
        """
        if not chunks:
            return None
        
        # Sort chunks by index
        chunks = sorted(chunks, key=lambda x: x[1])
        
        # Check if we have all chunks
        expected_chunks = (expected_length + 480 - 1) // 480
        
        print(f"[Handshake-RX-DEBUG] Reassemble: total_length={expected_length}, expected_chunks={expected_chunks}, received={len(chunks)}")
        
        if len(chunks) < expected_chunks:
            return None  # Still waiting for more chunks
        
        # Reassemble
        data = b''.join(chunk[2] for chunk in chunks)
        
        print(f"[Handshake-RX-DEBUG] Reassembled {len(data)} bytes, trimming to {expected_length}")
        
        return data[:expected_length]  # Trim to exact length
    
    def _reassemble_chunks(self):
        """
        Reassemble chunked data from receive buffer.
        
        Returns:
            bytes if complete message received, None otherwise
        """
        if not self.receive_buffer:
            return None
        
        # Sort chunks by index
        chunks = sorted(self.receive_buffer, key=lambda x: x[1])
        
        # Check if we have all chunks
        total_length = chunks[0][0]
        expected_chunks = (total_length + 480 - 1) // 480  # Match MAX_CHUNK_SIZE
        
        print(f"[Handshake-RX-DEBUG] Reassemble: total_length={total_length}, expected_chunks={expected_chunks}, received={len(chunks)}")
        
        if len(chunks) < expected_chunks:
            return None  # Still waiting for more chunks
        
        # Reassemble
        data = b''.join(chunk[2] for chunk in chunks)
        
        print(f"[Handshake-RX-DEBUG] Reassembled {len(data)} bytes, trimming to {total_length}")
        
        # Clear buffer
        self.receive_buffer = []
        
        return data[:total_length]  # Trim to exact length
    
    def add_received_chunk(self, total_length, chunk_index, chunk_data):
        """
        Add a received chunk to the buffer.
        
        This is called by the RxCharacteristic when data arrives.
        
        Args:
            total_length: Total length of the message
            chunk_index: Index of this chunk
            chunk_data: The chunk data
        """
        self.receive_buffer.append((total_length, chunk_index, chunk_data))
        print(f"[Handshake-RX] Received chunk {chunk_index} ({len(chunk_data)} bytes)")


class HandshakeReceiveQueue:
    """
    Global queue for managing handshake receive operations.
    
    This allows the RxCharacteristic to route handshake messages
    to the appropriate transport instance.
    """
    
    def __init__(self):
        self.transports = {}  # mac -> BLEHandshakeTransport
    
    def register_transport(self, mac, transport):
        """Register a transport for a specific MAC address."""
        self.transports[mac] = transport
    
    def unregister_transport(self, mac):
        """Unregister a transport."""
        if mac in self.transports:
            del self.transports[mac]
    
    def route_chunk(self, mac, total_length, chunk_index, chunk_data):
        """Route a received chunk to the appropriate transport."""
        if mac in self.transports:
            self.transports[mac].add_received_chunk(total_length, chunk_index, chunk_data)
            return True
        return False


# Global receive queue
handshake_receive_queue = HandshakeReceiveQueue()
