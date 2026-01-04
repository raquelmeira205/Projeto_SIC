import time
import threading
import json
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload
from common.crypto_utils import generate_mac, verify_mac
from common.security_handshake import SecurityHandshake
from common.ble_handshake_transport import BLEHandshakeTransport, handshake_receive_queue
from common.crl_manager import CRLManager
from common.pki_utils import extract_nid_from_cert
from node.dtls_client import DtlsSession
from common.dtls_structs import ContentType

HEARTBEAT_INTERVAL = 5.0
MAX_MISSED = 3
TIMEOUT_LIMIT = HEARTBEAT_INTERVAL * MAX_MISSED


class Router:
    """
    Controlador central de rede do nó.
    Gerencia a tabela de roteamento, o envio/recebimento de pacotes,
    a segurança de link (MAC/Replay Protection), o tratamento de Heartbeats,
    e a sessão DTLS fim-a-fim.
    """

    def __init__(self, my_nid, security_module, ble_manager, app_layer=None, cert_path=None, key_path=None, ca_cert_path=None):
        self.my_nid = my_nid
        self.security = security_module
        self.ble = ble_manager
        self.app_layer = app_layer
        
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path

        self.crl_manager = CRLManager("crl_node.json")

        self.forwarding_table = {}
        self.uplink_connection = None
        self.downlink_connections = set()

        self.blocked_downlinks = set()
        
        self.link_keys = {} 
        self.replay_counters = {}
        self.my_counters = {}
        self.pending_incoming_handshakes = set()

        self.last_heartbeat_time = 0
        self.last_heartbeat_seq = -1
        self.hops_to_sink = -1

        self.downlink_missed_heartbeats = {}

        self._stop_monitor = False
        
        self.sink_nid = None
        self.stats = {
            "lost_heartbeats": 0,
            "routed_messages": 0,
            "received_messages": []
        }
        
        self.dtls_session = None
        self.pending_dtls_packets = []

        threading.Thread(target=self._monitor_heartbeat_timeout, daemon=True).start()

    def set_uplink(self, connection_handle, parent_hops):
        """
        Define um novo uplink e inicia o handshake de segurança.
        
        :param connection_handle: Endereço MAC ou identificador da conexão.
        :param parent_hops: Contagem de hops do pai.
        """
        self.uplink_connection = connection_handle
        
        if parent_hops == 255 or parent_hops == -1:
            self.hops_to_sink = -1
            ble_hop_val = 255
        else:
            self.hops_to_sink = parent_hops + 1
            ble_hop_val = self.hops_to_sink

        self.ble.hop_count = ble_hop_val
        self.ble.update_advertisement()

        self.last_heartbeat_time = time.time()
        
        time.sleep(2.0)

        if connection_handle not in self.link_keys:
             try:
                 session_key, peer_cert = self.perform_handshake(connection_handle, is_initiator=True)
                 self.link_keys[connection_handle] = session_key
                 self.my_counters[connection_handle] = 0
                 self.replay_counters[connection_handle] = 0
                 
                 if parent_hops == 0 and peer_cert:
                     self.security.update_sink_cert(peer_cert)
                     
             except Exception:
                 self.ble.disconnect_from_device(connection_handle)
                 raise

    def send_data_packet(self, dest_nid, payload, msg_type=MsgType.DATA):
        """Wrapper para enviar pacote de dados bruto."""
        self._route_data(self.my_nid, dest_nid, payload, msg_type)

    def establish_dtls_session(self):
        """Inicia a sessão DTLS com o Sink."""
        if not self.sink_nid:
             return
             
        self.dtls_session = DtlsSession(
            self.sink_nid, self.my_nid, 
            self.cert_path, self.key_path, self.ca_cert_path, 
            self
        )
        self.dtls_session.perform_handshake()

    def send_app_data(self, dest_nid, payload):
        """
        Envia dados da aplicação, usando criptografia fim-a-fim se o destino for o Sink.
        """
        if dest_nid == self.sink_nid:
            if not self.dtls_session:
                self.establish_dtls_session()
                self.pending_dtls_packets.append((dest_nid, payload))
                return True
                
            if self.dtls_session.state.value != 4:
                self.pending_dtls_packets.append((dest_nid, payload))
                return True
                
            try:
                record = self.dtls_session.send(payload)
                self._route_data(self.my_nid, dest_nid, record, MsgType.DATA)
                return True
            except Exception:
                return False
        else:
            self._route_data(self.my_nid, dest_nid, payload)
        
        return True

    def process_incoming_packet(self, packet_data, incoming_conn):
        """
        Processa pacotes recebidos (validação de segurança, roteamento, heartbeats).
        """
        try:
            src, dest, mtype, payload, seq, mac = PacketHeader.unpack(packet_data)

            if mtype != MsgType.HEARTBEAT:
                if incoming_conn not in self.link_keys:
                    return

                raw_key = self.link_keys[incoming_conn]
                if isinstance(raw_key, tuple):
                    key = raw_key[0]
                else:
                    key = raw_key
                
                if not isinstance(key, bytes):
                    return

                if not self._verify_security(incoming_conn, packet_data, seq, mac, session_key=key):
                    return

            if incoming_conn and src != self.my_nid:
                if self.forwarding_table.get(src) != incoming_conn:
                    self.forwarding_table[src] = incoming_conn

            if mtype == MsgType.HEARTBEAT:
                self._handle_heartbeat(payload, incoming_conn, src)
            
            elif mtype == MsgType.DTLS_HANDSHAKE:
                if dest == self.my_nid:
                    if self.dtls_session:
                        prev_state = self.dtls_session.state.value
                        self.dtls_session.handle_handshake_message(payload)
                        new_state = self.dtls_session.state.value
                        
                        if prev_state != 4 and new_state == 4:
                            while self.pending_dtls_packets:
                                p_dest, p_payload = self.pending_dtls_packets.pop(0)
                                self.send_app_data(p_dest, p_payload)
                else:
                    self._route_data(src, dest, payload, MsgType.DTLS_HANDSHAKE)
            
            elif mtype == MsgType.DATA:
                if dest == self.my_nid and src == self.sink_nid and self.dtls_session:
                    try:
                        ctype, plaintext = self.dtls_session.recv(payload)
                        if ctype == ContentType.APPLICATION_DATA:
                             if self.app_layer: self.app_layer.receive(src, plaintext)
                        elif ctype == ContentType.HANDSHAKE:
                             self.dtls_session.handle_handshake_message(payload)
                    except Exception:
                        pass
                else:
                    self._route_data(src, dest, payload)            

            elif mtype == MsgType.CONTROL:
                try:
                    data = json.loads(payload.decode('utf-8'))
                    if data.get("type") == "crl":
                        revoked = data.get("revoked", [])
                        if self.crl_manager:
                            if self.crl_manager.update_from_list(revoked):
                                for child in self.downlink_connections:
                                    self._send_authenticated_packet(child, src, b'\xFF'*16, MsgType.CONTROL, payload)
                except Exception:
                    pass

        except Exception as e:
            print(f"[Packet Error] {e}")

    def _verify_security(self, conn, packet_data, seq, received_mac, session_key=None):
        """Verifica a integridade (MAC) e replay protection do pacote."""
        if conn is None: 
            return True
        
        src_nid = packet_data[0:16]
        
        if session_key is None:
            if conn in self.link_keys:
                session_key = self.link_keys[conn]
                if isinstance(session_key, tuple):
                    session_key = session_key[0]
            else:
                return False
        
        key = session_key
        
        src, dest, mtype, payload, _, _ = PacketHeader.unpack(packet_data)
        check_packet = PacketHeader.pack(src, dest, mtype, payload, seq, b'\x00'*32)
        
        if not verify_mac(key, check_packet, received_mac):
            return False

        last_seq = self.replay_counters.get(conn, 0)
        if seq <= last_seq:
            return False
            
        self.replay_counters[conn] = seq
        return True

    def _handle_heartbeat(self, payload, incoming_conn, src_nid):
        """Processa heartbeats recebidos, gerencia failover e retransmit para filhos."""
        if self.uplink_connection and incoming_conn != self.uplink_connection:
            return
        
        if not self.uplink_connection and incoming_conn in self.link_keys:
            self.uplink_connection = incoming_conn
            self.last_heartbeat_time = time.time()
            self.ble.uplink_addr = incoming_conn
            self.ble.uplink_nid = src_nid
            self.ble.update_advertisement()

        if self.sink_nid != src_nid:
             if self.sink_nid is not None:
                 self.dtls_session = None
                 self.pending_dtls_packets = []
             self.sink_nid = src_nid

        seq, sig = HeartbeatPayload.unpack(payload)

        if not self.security.verify_sink_signature(seq.to_bytes(4, 'big'), sig):
            return

        if seq <= self.last_heartbeat_seq:
            return

        self.last_heartbeat_seq = seq
        self.last_heartbeat_time = time.time()

        failed_downlinks = []
        for child in list(self.downlink_connections):
            if child in self.blocked_downlinks:
                failed_downlinks.append(child)
                continue
                
            if not self._send_authenticated_packet(child, src_nid, b'\x00'*16, MsgType.HEARTBEAT, payload):
                failed_downlinks.append(child)

        for child in failed_downlinks:
            count = self.downlink_missed_heartbeats.get(child, 0) + 1
            self.downlink_missed_heartbeats[child] = count
            
            if count >= MAX_MISSED:
                self.ble.disconnect_from_device(child)
                self.handle_disconnection(child)

    def _monitor_heartbeat_timeout(self):
        """Monitora timeout do heartbeat do uplink."""
        while not self._stop_monitor:
            time.sleep(1)
            if self.uplink_connection:
                if (time.time() - self.last_heartbeat_time) > TIMEOUT_LIMIT:
                    self.stats["lost_heartbeats"] += 1
                    self.ble.disconnect_from_device(self.uplink_connection) 

    def handle_disconnection(self, conn):
        """Trata a desconexão de um dispositivo (uplink ou downlink)."""
        to_del = [n for n, c in self.forwarding_table.items() if c == conn]
        for n in to_del: del self.forwarding_table[n]
        
        if conn in self.downlink_connections:
            self.downlink_connections.remove(conn)
        if conn in self.downlink_missed_heartbeats:
            del self.downlink_missed_heartbeats[conn]

        if conn == self.uplink_connection:
            self.uplink_connection = None
            self.hops_to_sink = -1
            self.ble.hop_count = 255
            self.ble.update_advertisement()
            self.hops_to_sink = -1
            self.forwarding_table.clear()

            kids = list(self.downlink_connections)
            for k in kids: self.ble.disconnect_from_device(k)
            self.downlink_connections.clear()

    def _route_data(self, src, dest, payload, msg_type=MsgType.DATA):
        """Roteia o pacote para o próximo salto adequado."""
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
            self._send_authenticated_packet(target_conn, src, dest, msg_type, payload)

    def _send_authenticated_packet(self, conn, src, dest, msg_type, payload):
        """Cálcula o MAC, empacota e envia o pacote de forma segura."""
        if conn not in self.link_keys:
             return False
             
        raw_key = self.link_keys[conn]
        
        if isinstance(raw_key, tuple):
            key = raw_key[0]
        else:
            key = raw_key
        
        if not isinstance(key, bytes):
            return False
        
        if not isinstance(src, bytes):
            if isinstance(src, str):
                src = src.encode('utf-8')[:16].ljust(16, b'\x00')
            else:
                return False
        
        if not isinstance(dest, bytes):
            if isinstance(dest, str):
                dest = dest.encode('utf-8')[:16].ljust(16, b'\x00')
            else:
                return False
        
        if payload is None:
            payload = b''
        elif isinstance(payload, str):
            payload = payload.encode('utf-8')
        elif not isinstance(payload, bytes):
            try:
                payload = bytes(payload)
            except:
                return False
        
        self.my_counters[conn] += 1
        seq = self.my_counters[conn]
        
        try:
            temp_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, b'\x00'*32)
            mac = generate_mac(key, temp_packet)
            final_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, mac)
            return self.ble.send_packet(conn, final_packet)
        except Exception:
            return False
    
    def perform_handshake(self, connection_mac, is_initiator=True):
        """
        Realiza o handshake de segurança com um par.
        
        :param connection_mac: Endereço MAC do par.
        :param is_initiator: Se somos o iniciador.
        :return: Tupla (session_key, peer_cert).
        """
        if not all([self.cert_path, self.key_path, self.ca_cert_path]):
            raise RuntimeError("Caminhos de certificado não configurados")
        
        transport = BLEHandshakeTransport(connection_mac, self.ble, is_initiator=is_initiator)
        handshake_receive_queue.register_transport(connection_mac, transport)
        
        try:
            handshake = SecurityHandshake(self.cert_path, self.key_path, self.ca_cert_path, self.crl_manager)
            handshake.perform_handshake(transport)
            session_key = handshake.session_key
            
            if not session_key or len(session_key) != 32:
                raise RuntimeError("Chave de sessão inválida derivada")
            
            return session_key, handshake.peer_cert
            
        finally:
            handshake_receive_queue.unregister_transport(connection_mac)
    
    def handle_incoming_handshake(self, peer_mac):
        """
        Lida com uma solicitação de handshake recebida (responder).
        
        :param peer_mac: MAC do solicitante.
        """
        if peer_mac in self.link_keys:
            return
        
        if peer_mac in self.pending_incoming_handshakes:
            return
        
        self.pending_incoming_handshakes.add(peer_mac)
        
        def _run_handshake():
            try:
                session_key, peer_cert = self.perform_handshake(peer_mac, is_initiator=False)
                
                self.link_keys[peer_mac] = session_key
                self.my_counters[peer_mac] = 0
                self.replay_counters[peer_mac] = 0
                
                self.downlink_connections.add(peer_mac)
                self.downlink_missed_heartbeats[peer_mac] = 0
                
                if peer_cert:
                    try:
                        peer_nid = extract_nid_from_cert(peer_cert)
                        if peer_nid:
                             self._update_forwarding_table(peer_nid, peer_mac)
                    except Exception:
                        pass

            except Exception:
                pass
            finally:
                self.pending_incoming_handshakes.discard(peer_mac)
        
        threading.Thread(target=_run_handshake, daemon=True).start()

    def _update_forwarding_table(self, nid_bytes, mac_addr):
        self.forwarding_table[nid_bytes] = mac_addr

    def toggle_heartbeat_block(self, child_conn):
        """
        Ativa/Desativa o bloqueio de heartbeats para simulação de falhas.
        """
        if child_conn in self.blocked_downlinks:
            self.blocked_downlinks.remove(child_conn)
            return False 
        else:
            self.blocked_downlinks.add(child_conn)
            return True 

    def get_downlinks_status(self):
        """
        Retorna o status dos downlinks (conectados e bloqueados ou não).
        """
        status = []
        for child in self.downlink_connections:
            is_blocked = child in self.blocked_downlinks
            status.append((child, is_blocked))
        return status