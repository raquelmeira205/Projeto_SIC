import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload

HEARTBEAT_INTERVAL = 5.0
MAX_MISSED = 3
TIMEOUT_LIMIT = HEARTBEAT_INTERVAL * MAX_MISSED

class Router:
    def __init__(self, my_nid, security_module, ble_manager, app_layer=None):
        self.my_nid = my_nid
        self.security = security_module
        self.ble = ble_manager
        self.app_layer = app_layer

        self.forwarding_table = {}
        self.uplink_connection = None
        self.downlink_connections = set()
        
        self.last_heartbeat_time = 0
        self.last_heartbeat_seq = -1
        self.hops_to_sink = -1

        self._stop_monitor = False
        threading.Thread(target=self._monitor_heartbeat_timeout, daemon=True).start()

    def set_uplink(self, connection_handle, hops):
        self.uplink_connection = connection_handle
        self.hops_to_sink = hops + 1
        self.last_heartbeat_time = time.time()

    def process_incoming_packet(self, packet_data, incoming_conn):
        try:
            src, dest, mtype, payload = PacketHeader.unpack(packet_data)

            if incoming_conn and src != self.my_nid:
                if self.forwarding_table.get(src) != incoming_conn:
                    self.forwarding_table[src] = incoming_conn
                
                # Track Downlinks: If it's not our uplink, it's a child/neighbor downlink
                if incoming_conn != self.uplink_connection:
                    self.downlink_connections.add(incoming_conn)

            if mtype == MsgType.HEARTBEAT:
                self._handle_heartbeat(payload, incoming_conn)
            elif mtype == MsgType.DATA:
                self._route_data(src, dest, payload, packet_data)

        except Exception as e:
            print(f"Packet Error: {e}")

    def _handle_heartbeat(self, payload, incoming_conn):
        if incoming_conn != self.uplink_connection:
            return

        seq, sig = HeartbeatPayload.unpack(payload)

        if not self.security.verify_sink_signature(seq.to_bytes(4, 'big'), sig):
            return

        if seq <= self.last_heartbeat_seq:
            return

        self.last_heartbeat_seq = seq
        self.last_heartbeat_time = time.time()

        fwd_packet = PacketHeader.pack(b'\x00'*16, b'\x00'*16, MsgType.HEARTBEAT, payload)
        
        # Single Broadcast call instead of iterating
        self.ble.send_downstream(fwd_packet)


    def _monitor_heartbeat_timeout(self):
        while not self._stop_monitor:
            time.sleep(1)
            if self.uplink_connection:
                if (time.time() - self.last_heartbeat_time) > TIMEOUT_LIMIT:
                    self.ble.disconnect(self.uplink_connection) 

    def handle_disconnection(self, conn):
        to_del = [n for n, c in self.forwarding_table.items() if c == conn]
        for n in to_del: del self.forwarding_table[n]
        
        if conn in self.downlink_connections:
            self.downlink_connections.remove(conn)

        if conn == self.uplink_connection:
            self.uplink_connection = None
            self.hops_to_sink = -1
            self.forwarding_table.clear()

            kids = list(self.downlink_connections)
            for k in kids: self.ble.disconnect(k)
            self.downlink_connections.clear()

    def _route_data(self, src, dest, payload, raw):
        if dest == self.my_nid:
            if self.app_layer: self.app_layer.receive(src, payload)
        elif dest in self.forwarding_table:
            self.ble.send_packet(self.forwarding_table[dest], raw)
        elif self.uplink_connection:
            self.ble.send_packet(self.uplink_connection, raw)