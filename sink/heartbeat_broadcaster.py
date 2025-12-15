
import time
import threading
import logging
from common.packet_headers import PacketHeader, MsgType, HeartbeatPayload
from common.security_primitives import sign_data
from common.constants import HEARTBEAT_INTERVAL

class HeartbeatBroadcaster:
    def __init__(self, sink_identity, multicaster):
        self.identity = sink_identity
        self.multicaster = multicaster
        self.running = False
        self.sequence_number = 0
        self.known_nodes_macs = set() # Needs to be populated by some discovery or registration mechanism

    def register_node(self, mac):
        self.known_nodes_macs.add(mac)

    def start(self):
        self.running = True
        t = threading.Thread(target=self._loop)
        t.daemon = True
        t.start()
        logging.info("HeartbeatBroadcaster started")

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._broadcast_heartbeat()
            except Exception as e:
                logging.error(f"Error in heartbeat loop: {e}")
            time.sleep(HEARTBEAT_INTERVAL)

    def _broadcast_heartbeat(self):
        # 1. Prepare Payload
        # Signature covers sequence number
        # We sign (seq_num bits)
        data_to_sign = self.sequence_number.to_bytes(4, 'big')
        signature = sign_data(self.identity.private_key, data_to_sign)
        
        hb_payload = HeartbeatPayload.pack(self.sequence_number, signature)
        
        # 2. Wrap in Packet
        # Broadcast/Multicast Packet? MsgType.HEARTBEAT
        # Dest NID = 0 (Broadcast) or specific? 
        # Requirement: "multi-unicast logic"
        
        packet = PacketHeader.pack(
            source_nid=self.identity.nid.bytes,
            dest_nid=b'\x00'*16, # Broadcast NID convention?
            msg_type=MsgType.HEARTBEAT,
            payload=hb_payload
        )

        logging.info(f"Sending Heartbeat #{self.sequence_number} to {len(self.known_nodes_macs)} nodes")
        
        # 3. Send
        if self.known_nodes_macs:
            self.multicaster.multicast(list(self.known_nodes_macs), packet)
        
        self.sequence_number += 1
