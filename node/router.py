import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload
from common.crypto_utils import generate_mac, verify_mac

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
        
        # Link Layer Security State
        # Map: connection_handle -> session_key (bytes)
        self.link_keys = {} 
        # Map: connection_handle -> last_valid_sequence_number (int)
        self.replay_counters = {}
        # Map: connection_handle -> my_outgoing_sequence_number (int)
        self.my_counters = {}

        self.last_heartbeat_time = 0
        self.last_heartbeat_seq = -1
        self.hops_to_sink = -1

        self._stop_monitor = False
        
        # Stats & UI Support
        self.sink_nid = None
        self.stats = {
            "lost_heartbeats": 0,
            "routed_messages": 0,
            "received_messages": [] # List of (sender_nid, msg_bytes)
        }

        threading.Thread(target=self._monitor_heartbeat_timeout, daemon=True).start()

    def set_uplink(self, connection_handle, hops, session_key=None):
        self.uplink_connection = connection_handle
        self.hops_to_sink = hops + 1
        self.last_heartbeat_time = time.time()
        # Init security state for uplink
        if session_key:
             self.link_keys[connection_handle] = session_key
        elif connection_handle not in self.link_keys:
             # Fallback for testing only
             self.link_keys[connection_handle] = b'DEFAULT_TEST_KEY_1234567890123456'
             self.my_counters[connection_handle] = 0
             self.replay_counters[connection_handle] = 0

    def send_app_data(self, dest_nid, payload):
        # Delegate directly to route_data, which handles packet creation
        self._route_data(self.my_nid, dest_nid, payload)
        return True

    def process_incoming_packet(self, packet_data, incoming_conn):
        try:
             # 1. Unpack
            src, dest, mtype, payload, seq, mac = PacketHeader.unpack(packet_data)

            # 2. Security Checks
            if not self._verify_security(incoming_conn, packet_data, seq, mac):
                print(f"[!] Falha de segurança no pacote de {incoming_conn}")
                return

            if incoming_conn and src != self.my_nid:
                if self.forwarding_table.get(src) != incoming_conn:
                    self.forwarding_table[src] = incoming_conn
                    # Initialize key placeholder if new connection found via forwarding? 
                    # Ideally handshake happens first.

            if mtype == MsgType.HEARTBEAT:
                self._handle_heartbeat(payload, incoming_conn, src)
            elif mtype == MsgType.DATA:
                self._route_data(src, dest, payload)

        except Exception as e:
            print(f"Packet Error: {e}")

    def _verify_security(self, conn, packet_data, seq, received_mac):
        # Se for loopback/processamento local, assumir seguro ou tratar diferente
        if conn is None: 
            return True
            
        # 1. Retrieve Key
        key = self.link_keys.get(conn, b'DEFAULT_TEST_KEY_1234567890123456')
        
        # 2. Reconstruct Header with Zero MAC for verification
        # Necessitamos de reconstruir o cabeçalho exato usado para gerar o MAC
        # O PacketHeader.pack coloca os bytes na ordem certa.
        # unpack já separou os dados.
        # Recriamos o pacote com MAC zerado:
        src, dest, mtype, payload, _, _ = PacketHeader.unpack(packet_data)
        
        # Recriar pacote SOMENTE para verificar MAC (seq_num faz parte do input)
        check_packet = PacketHeader.pack(src, dest, mtype, payload, seq, b'\x00'*32)
        
        if not verify_mac(key, check_packet, received_mac):
            print(f"[sec] MAC Inválido de {conn}")
            return False

        # 3. Replay Protection
        last_seq = self.replay_counters.get(conn, 0)
        if seq <= last_seq:
            print(f"[sec] Replay detetado de {conn} (Seq {seq} <= {last_seq})")
            return False
            
        self.replay_counters[conn] = seq
        return True

    def _handle_heartbeat(self, payload, incoming_conn, src_nid):
        if incoming_conn != self.uplink_connection:
            return

        # Capturar Sink NID
        if self.sink_nid != src_nid:
             self.sink_nid = src_nid

        seq, sig = HeartbeatPayload.unpack(payload)

        if not self.security.verify_sink_signature(seq.to_bytes(4, 'big'), sig):
            return

        if seq <= self.last_heartbeat_seq:
            return

        self.last_heartbeat_seq = seq
        self.last_heartbeat_time = time.time()

        # Re-encapsulate heartbeat for downlinks
        # NOTE: Header MAC is 0x00*16 for addr? No, src/dest are just headers.
        # But we must send to each child individually to sign correctly.
        for child in self.downlink_connections:
            self._send_authenticated_packet(child, b'\x00'*16, b'\x00'*16, MsgType.HEARTBEAT, payload)

    def _monitor_heartbeat_timeout(self):
        while not self._stop_monitor:
            time.sleep(1)
            if self.uplink_connection:
                if (time.time() - self.last_heartbeat_time) > TIMEOUT_LIMIT:
                    self.stats["lost_heartbeats"] += 1
                    self.ble.disconnect_from_device(self.uplink_connection) 

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
            for k in kids: self.ble.disconnect_from_device(k)
            self.downlink_connections.clear()

    def _route_data(self, src, dest, payload):
        target_conn = None
        
        if dest == self.my_nid:
            if self.app_layer: self.app_layer.receive(src, payload)
            return
        elif dest in self.forwarding_table:
            target_conn = self.forwarding_table[dest]
        elif self.uplink_connection:
            target_conn = self.uplink_connection

        if target_conn:
            self.stats["routed_messages"] += 1
            if self._send_authenticated_packet(target_conn, src, dest, MsgType.DATA, payload):
                pass
            else:
                print(f"[!] Falha ao enviar para {target_conn}")

    def _send_authenticated_packet(self, conn, src, dest, msg_type, payload):
        if conn not in self.link_keys:
             self.link_keys[conn] = b'DEFAULT_TEST_KEY_1234567890123456'
             self.my_counters[conn] = 0
             
        key = self.link_keys[conn]
        self.my_counters[conn] += 1
        seq = self.my_counters[conn]
        
        # 1. Pack with Zero MAC
        temp_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, b'\x00'*32)
        
        # 2. Calculate MAC
        mac = generate_mac(key, temp_packet)
        
        # 3. Final Pack
        final_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, mac)
        
        return self.ble.send_packet(conn, final_packet)