import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload

class HeartbeatService:
    def __init__(self, sink_nid, connection_manager, security_module):
        self.sink_nid = sink_nid
        self.conn_manager = connection_manager 
        self.security = security_module        
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
            data_to_sign = self.sequence_number.to_bytes(4, 'big')
            signature = self.security.sign_data(data_to_sign)
            
            hb_payload = HeartbeatPayload.pack(self.sequence_number, signature)
            
            packet = PacketHeader.pack(
                source_nid=self.sink_nid,
                dest_nid=b'\x00'*16, 
                msg_type=MsgType.HEARTBEAT,
                payload=hb_payload
            )

            print(f"[Sink] A enviar Heartbeat #{self.sequence_number}")
            
            # Send to all authenticated links
            # Must iterate over keys to get MACs
            # Use list() to avoid runtime error if dict changes size
            if hasattr(self.conn_manager, 'session_keys'):
                for mac in list(self.conn_manager.session_keys.keys()):
                    # Heartbeats don't strictly need MAC (Node skips verification), 
                    # but using send_authenticated_packet is consistent and handles sequence numbers.
                    # Note: We pass original packet components to send_authenticated_packet
                    # payload is hb_payload
                    self.conn_manager.send_authenticated_packet(
                        mac, 
                        self.sink_nid, 
                        b'\x00'*16, 
                        MsgType.HEARTBEAT, 
                        hb_payload
                    )

            self.sequence_number += 1
            time.sleep(5) 

    def stop(self):
        self.running = False