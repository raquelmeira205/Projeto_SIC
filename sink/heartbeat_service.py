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
            
            print(f"[Sink] A enviar Heartbeat #{self.sequence_number}")
            self.conn_manager.send_authenticated_to_all(
                src_nid=self.sink_nid,
                dest_nid=b'\x00'*16,
                msg_type=MsgType.HEARTBEAT,
                payload=hb_payload
            )

            self.sequence_number += 1
            time.sleep(5) 

    def stop(self):
        self.running = False