import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload
from common.security import compute_mac

class HeartbeatService:
    def __init__(self, sink_nid, connection_manager):
        self.sink_nid = sink_nid
        self.conn_manager = connection_manager 
        self.running = False
        self.sequence_number = 0

    def start(self):
        self.running = True
        thread = threading.Thread(target=self._heartbeat_loop)
        thread.daemon = True 
        thread.start()

    def _heartbeat_loop(self):
        print("[Sink] Serviço de Heartbeat iniciado.")
        while self.running:
            # Send heartbeat to all connected nodes with established session keys
            for mac, session_key in list(self.conn_manager.session_keys.items()):
                try:
                    # Create heartbeat payload (just sequence number, no signature needed)
                    # The MAC will provide authentication
                    hb_payload = self.sequence_number.to_bytes(4, 'big')
                    
                    # Create packet with zero MAC initially
                    packet = PacketHeader.pack(
                        source_nid=self.sink_nid,
                        dest_nid=b'\x00'*16,  # Broadcast
                        msg_type=MsgType.HEARTBEAT,
                        payload=hb_payload,
                        seq_num=self.sequence_number,
                        mac=b'\x00'*32  # Placeholder
                    )
                    
                    # Compute MAC using session key
                    mac_value = compute_mac(session_key, packet)
                    
                    # Recreate packet with actual MAC
                    packet = PacketHeader.pack(
                        source_nid=self.sink_nid,
                        dest_nid=b'\x00'*16,
                        msg_type=MsgType.HEARTBEAT,
                        payload=hb_payload,
                        seq_num=self.sequence_number,
                        mac=mac_value
                    )
                    
                    print(f"[Sink] Sending Heartbeat #{self.sequence_number} to {mac}")
                    self.conn_manager._send_packet(mac, list(packet))
                    
                except Exception as e:
                    print(f"[Sink] Error sending heartbeat to {mac}: {e}")
            
            self.sequence_number += 1
            time.sleep(5) 

    def stop(self):
        self.running = False