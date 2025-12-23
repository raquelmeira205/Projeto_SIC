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
    
    def __init__(self, mac_address, is_initiator=True, timeout=10.0):
        """
        Initialize BLE handshake transport.
        
        Args:
            mac_address: MAC address of the peer device
            is_initiator: True if this side initiates the handshake
            timeout: Timeout in seconds for receive operations
        """
        self.mac = mac_address
        self.is_initiator = is_initiator
        self.timeout = timeout
        self.rx_char = None
        self.receive_buffer = []
        self.receive_complete = False
        
    def _get_characteristic(self):
        """Get the GATT characteristic for communication."""
        if not self.rx_char:
            self.rx_char = get_gatt_characteristic(self.mac, SIC_RX_CHAR_UUID)
            if not self.rx_char:
                raise RuntimeError(f"Failed to get GATT characteristic for {self.mac}")
        return self.rx_char
    
    def send(self, data):
        """
        Send data over BLE GATT characteristic.
        
        Args:
            data: bytes to send
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        char = self._get_characteristic()
        
        # BLE GATT has MTU limitations (typically 512 bytes max)
        # For handshake, we need to send certificates and keys which can be large
        # We'll chunk the data with a simple framing protocol:
        # [total_length (4 bytes)][chunk_index (2 bytes)][chunk_data]
        
        MAX_CHUNK_SIZE = 500  # Conservative chunk size
        total_length = len(data)
        num_chunks = (total_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        
        print(f"[Handshake-TX] Sending {total_length} bytes in {num_chunks} chunks to {self.mac}")
        
        for i in range(num_chunks):
            start = i * MAX_CHUNK_SIZE
            end = min(start + MAX_CHUNK_SIZE, total_length)
            chunk_data = data[start:end]
            
            # Frame: [total_length][chunk_index][chunk_data]
            frame = (
                total_length.to_bytes(4, 'big') +
                i.to_bytes(2, 'big') +
                chunk_data
            )
            
            try:
                char.WriteValue(list(frame), {'type': GLib.Variant('s', 'command')})
                time.sleep(0.05)  # Small delay between chunks
            except Exception as e:
                raise RuntimeError(f"Failed to send chunk {i}/{num_chunks}: {e}")
        
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
        
        # In the actual implementation, the RxCharacteristic will populate
        # a receive queue that we poll here. For now, we'll implement a 
        # simplified version that expects the router to call set_received_data()
        
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            if self.receive_buffer:
                # Reassemble chunks
                data = self._reassemble_chunks()
                if data is not None:
                    print(f"[Handshake-RX] Received {len(data)} bytes")
                    return data
            time.sleep(0.1)
        
        raise TimeoutError(f"Timeout waiting for data from {self.mac}")
    
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
        expected_chunks = (total_length + 500 - 1) // 500
        
        if len(chunks) < expected_chunks:
            return None  # Still waiting for more chunks
        
        # Reassemble
        data = b''.join(chunk[2] for chunk in chunks)
        
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
