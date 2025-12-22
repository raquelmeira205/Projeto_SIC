
import queue
import time
from common.packet_structs import PacketHeader, MsgType, NID_SIZE

class BLEHandshakeTransport:
    def __init__(self, ble_manager, peer_mac, my_nid, peer_nid):
        self.ble = ble_manager
        self.peer_mac = peer_mac
        self.my_nid = my_nid
        self.peer_nid = peer_nid # Should be known or 0xFFFF? Handshake usually validates this.
        self.receive_queue = queue.Queue()
        self.timeout = 10.0

    def send(self, data: bytes):
        # We need to wrap this in a Packet? 
        # The SecurityHandshake sends raw bytes (PEM certs, signatures).
        # We must encapsulate in PacketHeader with MsgType.HANDSHAKE
        
        # Determine payload chunks if needed? 
        # BLE MTU is small, but PacketHeader logic might handle large payloads if implemented, 
        # or we rely on the underlying BLE fragmentation if 'simplepyble'/BlueZ handles it.
        # Assuming we can send reasonable size chunks or the underlying layer handles it.
        # For certificates (kB size), we might need application level fragmentation if BLE doesn't auto-fragment.
        # However, `ble_manager.send_packet` writes to a characteristic.
        # The `PacketHeader` structure has a 2-byte payload length, so max 65535.
        
        # Let's assume we can send it as one block for now, or the lower layer handles GATT fragmentation.
        
        packet = PacketHeader.pack(
            self.my_nid, 
            self.peer_nid if self.peer_nid else b'\x00'*NID_SIZE, # Dest might not be known yet?
            MsgType.HANDSHAKE, 
            data
        )
        
        success = self.ble.send_packet(self.peer_mac, packet)
        if not success:
            raise IOError(f"Failed to send Handshake packet to {self.peer_mac}")

    def receive(self) -> bytes:
        try:
            # Block until data is available
            data = self.receive_queue.get(block=True, timeout=self.timeout)
            return data
        except queue.Empty:
            raise TimeoutError("Handshake receive timeout")

    def on_packet_received(self, payload: bytes):
        # Called by Main when a HANDSHAKE packet arrives
        self.receive_queue.put(payload)
