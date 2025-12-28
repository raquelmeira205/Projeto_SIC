import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload
from common.crypto_utils import generate_mac, verify_mac
from common.security_handshake import SecurityHandshake
from common.ble_handshake_transport import BLEHandshakeTransport, handshake_receive_queue
from common.crl_manager import CRLManager

HEARTBEAT_INTERVAL = 5.0
MAX_MISSED = 3
TIMEOUT_LIMIT = HEARTBEAT_INTERVAL * MAX_MISSED

class Router:
    def __init__(self, my_nid, security_module, ble_manager, app_layer=None, cert_path=None, key_path=None, ca_cert_path=None):
        self.my_nid = my_nid
        self.security = security_module
        self.ble = ble_manager
        self.app_layer = app_layer
        
        # Certificate paths for handshake
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path

        self.crl_manager = CRLManager("crl_node.json") # Nodes might have their own local copy

        self.forwarding_table = {}
        self.uplink_connection = None
        self.downlink_connections = set()

        self.blocked_downlinks = set()
        
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
        
        # DTLS Session for end-to-end security with Sink
        self.dtls_session = None

        threading.Thread(target=self._monitor_heartbeat_timeout, daemon=True).start()

    def set_uplink(self, connection_handle, hops):
        self.uplink_connection = connection_handle
        self.hops_to_sink = hops + 1
        self.last_heartbeat_time = time.time()

        print(f"[Router] Conectado a {connection_handle}. A aguardar estabilização do link...")
        # pausa para o BlueZ negociar MTU e intervalos
        time.sleep(2.0)

        # Init security state for uplink if not exists
        if connection_handle not in self.link_keys:
             # Perform handshake to establish session key
             try:
                 session_key = self.perform_handshake(connection_handle, is_initiator=True)
                 self.link_keys[connection_handle] = session_key
                 self.my_counters[connection_handle] = 0
                 self.replay_counters[connection_handle] = 0
                 print(f"[Router] Handshake com uplink {connection_handle} concluído")
             except Exception as e:
                 print(f"[!] Handshake falhou com {connection_handle}: {e}")
                 # Disconnect on handshake failure
                 self.ble.disconnect_from_device(connection_handle)
                 raise

    def establish_dtls_session(self):
        """Establish DTLS session with Sink for end-to-end security"""
        if not self.sink_nid:
            raise RuntimeError("Sink NID not known yet (wait for heartbeat)")
        
        from node.dtls_client import DtlsSession
        
        print("[Router] Establishing DTLS session with Sink...")
        self.dtls_session = DtlsSession(
            sink_nid=self.sink_nid,
            my_nid=self.my_nid,
            cert_path=self.cert_path,
            key_path=self.key_path,
            ca_cert_path=self.ca_cert_path,
            router=self
        )
        
        # Perform handshake
        self.dtls_session.perform_handshake()
        print("[Router] DTLS session established!")
    
    def send_app_data(self, dest_nid, payload):
        """Send application data (encrypted with DTLS if destination is Sink)"""
        if dest_nid == self.sink_nid:
            # End-to-end encryption with DTLS
            if not self.dtls_session or self.dtls_session.state.value != "ESTABLISHED":
                print("[!] DTLS session not established. Establishing now...")
                self.establish_dtls_session()
            
            # Encrypt payload with DTLS
            dtls_record = self.dtls_session.send(payload)
            
            # Send DTLS record via Router (hop-by-hop MAC will be applied)
            self._route_data(self.my_nid, dest_nid, dtls_record, MsgType.DATA)
        else:
            # Direct routing (no DTLS for non-Sink destinations)
            self._route_data(self.my_nid, dest_nid, payload, MsgType.DATA)
        
        return True

    def process_incoming_packet(self, packet_data, incoming_conn):
        try:
             # 1. Unpack
            src, dest, mtype, payload, seq, mac = PacketHeader.unpack(packet_data)

            # 2. Security Checks (skip MAC verification for HEARTBEAT - uses signature instead)
            if mtype != MsgType.HEARTBEAT:
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
            elif mtype == MsgType.DTLS_HANDSHAKE:
                # DTLS handshake message - pass to DTLS session
                if self.dtls_session:
                    self.dtls_session.handle_handshake_message(payload)
                else:
                    print("[!] Received DTLS handshake but no session exists")
            elif mtype == MsgType.DATA:
                # Check if this is DTLS encrypted data from Sink
                if src == self.sink_nid and self.dtls_session:
                    try:
                        # Decrypt DTLS record
                        plaintext = self.dtls_session.recv(payload)
                        # Deliver to application layer
                        if self.app_layer:
                            self.app_layer.receive(src, plaintext)
                    except Exception as e:
                        print(f"[!] DTLS decryption failed: {e}")
                else:
                    # Regular routing
                    self._route_data(src, dest, payload, MsgType.DATA)

            elif mtype == MsgType.CONTROL:
                # Handle Control Messages (e.g. CRL Updates)
                try:
                    import json
                    data = json.loads(payload.decode('utf-8'))
                    if data.get("type") == "crl":
                        revoked = data.get("revoked", [])
                        if self.crl_manager:
                            print(f"[Router] Received CRL Update with {len(revoked)} entries")
                            if self.crl_manager.update_from_list(revoked):
                                # If any change, propagate to downlinks
                                print("[Router] Forwarding CRL update to downlinks...")
                                for child in self.downlink_connections:
                                    # Forward original payload
                                    self._send_authenticated_packet(child, src, b'\xFF'*16, MsgType.CONTROL, payload)
                except Exception as e:
                    print(f"[Router] Error processing CONTROL message: {e}")

        except Exception as e:
            print(f"Packet Error: {e}")

    def _verify_security(self, conn, packet_data, seq, received_mac):
        # Se for loopback/processamento local, assumir seguro ou tratar diferente
        if conn is None: 
            return True
            
        # 1. Retrieve Key
        if conn not in self.link_keys:
            print(f"[!] Sem chave de sessão para {conn} - handshake não realizado")
            return False
        key = self.link_keys[conn]
        
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
        # If we have an uplink, only accept heartbeats from it
        # If we don't have an uplink but receive a valid heartbeat from a connection
        # with an established session key, automatically set it as uplink
        if self.uplink_connection and incoming_conn != self.uplink_connection:
            return
        
        # If no uplink but we have a session key with this connection, set it as uplink
        if not self.uplink_connection and incoming_conn in self.link_keys:
            print(f"[Router] Auto-setting {incoming_conn} as uplink (received heartbeat)")
            self.uplink_connection = incoming_conn
            self.last_heartbeat_time = time.time()
            # Also update BLE manager's uplink tracking
            self.ble.uplink_addr = incoming_conn
            self.ble.uplink_nid = src_nid
            # Hop count will be set to 1 (connected to Sink with hop=0)
            self.ble.hop_count = 1
            self.hops_to_sink = 1
            self.ble.update_advertisement()

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
            if child in self.blocked_downlinks:
                continue 
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

    def _route_data(self, src, dest, payload, msg_type=MsgType.DATA):
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
            if self._send_authenticated_packet(target_conn, src, dest, msg_type, payload):
                pass
            else:
                print(f"[!] Falha ao enviar para {target_conn}")

    def _send_authenticated_packet(self, conn, src, dest, msg_type, payload):
        if conn not in self.link_keys:
             print(f"[!] Sem chave de sessão para {conn} - não é possível enviar")
             return False
             
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
    
    def perform_handshake(self, connection_mac, is_initiator=True):
        """
        Perform security handshake with a peer device.
        
        Args:
            connection_mac: MAC address of the peer
            is_initiator: True if we initiate the handshake
            
        Returns:
            bytes: 32-byte session key
            
        Raises:
            Exception if handshake fails
        """
        if not all([self.cert_path, self.key_path, self.ca_cert_path]):
            raise RuntimeError("Certificate paths not configured for handshake")
        
        print(f"[Handshake] Iniciando handshake com {connection_mac} (initiator={is_initiator})")
        
        # Create transport with BLE manager
        transport = BLEHandshakeTransport(connection_mac, self.ble, is_initiator=is_initiator)
        handshake_receive_queue.register_transport(connection_mac, transport)
        
        try:
            # Create handshake instance
            handshake = SecurityHandshake(self.cert_path, self.key_path, self.ca_cert_path, self.crl_manager)
            
            # Perform handshake
            handshake.perform_handshake(transport)
            
            # Get session key
            session_key = handshake.session_key
            
            if not session_key or len(session_key) != 32:
                raise RuntimeError("Invalid session key derived")
            
            print(f"[Handshake] Concluído com {connection_mac}: {session_key[:8].hex()}...")
            
            return session_key
            
        finally:
            handshake_receive_queue.unregister_transport(connection_mac)

    def toggle_heartbeat_block(self, child_conn):
        """Ativa/Desativa o envio de heartbeats para um filho específico."""
        if child_conn in self.blocked_downlinks:
            self.blocked_downlinks.remove(child_conn)
            print(f"[Network Control] Heartbeats RESTAURADOS para {child_conn}")
            return False # Retorna False (não bloqueado)
        else:
            self.blocked_downlinks.add(child_conn)
            print(f"[Network Control] Heartbeats BLOQUEADOS para {child_conn}")
            return True # Retorna True (bloqueado)

    def get_downlinks_status(self):
        """Retorna lista de filhos e seu estado de bloqueio para a UI."""
        status = []
        for child in self.downlink_connections:
            is_blocked = child in self.blocked_downlinks
            status.append((child, is_blocked))
        return status