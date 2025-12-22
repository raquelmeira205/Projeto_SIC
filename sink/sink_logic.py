
import threading
import queue
from common.security_handshake import SecurityHandshake
from common.packet_structs import PacketHeader, MsgType, NID_SIZE
from common.crypto_utils import verify_mac
from common.ble_utils import get_gatt_characteristic, SIC_RX_CHAR_UUID

class SinkBLEHandshakeTransport:
    def __init__(self, mac_address, sink_nid):
        self.mac = mac_address
        self.sink_nid = sink_nid
        self.receive_queue = queue.Queue()
        self.timeout = 10.0
        
    def send(self, data: bytes):
        packet = PacketHeader.pack(
            self.sink_nid,
            b'\x00'*NID_SIZE, # Dest NID unknown or broadcast to link
            MsgType.HANDSHAKE,
            data
        )
        self._write_to_device(packet)

    def _write_to_device(self, packet):
        try:
            char = get_gatt_characteristic(self.mac, SIC_RX_CHAR_UUID)
            if char:
                char.WriteValue(packet, {})
        except Exception as e:
            print(f"[Sink-Transport] Failed to send to {self.mac}: {e}")

    def receive(self) -> bytes:
        try:
            return self.receive_queue.get(block=True, timeout=self.timeout)
        except queue.Empty:
            raise TimeoutError("Handshake receive timeout")

    def on_packet_received(self, payload):
        self.receive_queue.put(payload)

class SinkLogic:
    def __init__(self, sink_nid, cert_path, key_path, ca_cert_path):
        self.sink_nid = sink_nid
        self.security = SecurityHandshake(cert_path, key_path, ca_cert_path)
        # Map MAC -> Session Key
        self.child_keys = {}
        # Map MAC -> HandshakeTransport (if active)
        self.active_handshakes = {}
        
    def on_packet_received(self, data, sender_mac):
        try:
            # 1. Unpack Header (Peak)
            if len(data) < PacketHeader.SIZE:
                return

            src, dest, mtype, payload, seq, mac = PacketHeader.unpack(data)
            
            # 2. Handle Handshake
            if mtype == MsgType.HANDSHAKE:
                self._handle_handshake_packet(sender_mac, payload)
            else:
                self._handle_data_packet(sender_mac, data) 
                
        except Exception as e:
            print(f"[Sink] Packet Error from {sender_mac}: {e}")

    def _handle_handshake_packet(self, sender_mac, payload):
        # Check if we have an active transport for this sender
        if sender_mac not in self.active_handshakes:
             print(f"[Sink] New Handshake initiated by {sender_mac}")
             # Create Transport
             transport = SinkBLEHandshakeTransport(sender_mac, self.sink_nid)
             self.active_handshakes[sender_mac] = transport
             
             # Start Handshake in a thread (it blocks)
             threading.Thread(target=self._run_handshake, args=(sender_mac, transport), daemon=True).start()
             
        # Allow transport to process payload
        self.active_handshakes[sender_mac].on_packet_received(payload)

    def _run_handshake(self, mac, transport):
        try:
            # Sink is the "Server" / Responder
            self.security.perform_handshake(transport)
            session_key = self.security.session_key
            
            print(f"[Sink] Handshake Success with {mac}!")
            self.child_keys[mac] = session_key
            
        except Exception as e:
            print(f"[Sink] Handshake Failed with {mac}: {e}")
        finally:
            if mac in self.active_handshakes:
                del self.active_handshakes[mac]

    def _handle_data_packet(self, sender_mac, packet_data):
        # Verify MAC using session key
        if sender_mac not in self.child_keys:
            print(f"[Sink] Ignored packet from {sender_mac} (No Session)")
            return
            
        key = self.child_keys[sender_mac]
        src, dest, mtype, payload, seq, received_mac = PacketHeader.unpack(packet_data)
        
        # Verify
        # Reconstruct zero-mac header
        check_packet = PacketHeader.pack(src, dest, mtype, payload, seq, b'\x00'*32)
        if not verify_mac(key, check_packet, received_mac):
             print(f"[Sink] Security Alert: Invalid MAC from {sender_mac}")
             return
             
        # Process Data
        if mtype == MsgType.DATA:
             try:
                 msg_str = payload.decode('utf-8')
                 print(f"[Sink] DATA RECEIVED from {sender_mac}: {msg_str}")
             except:
                 print(f"[Sink] DATA RECEIVED from {sender_mac}: {payload}")
        elif mtype == MsgType.HEARTBEAT:
             # Pass to HB Service (Mocked here or real)
             pass
