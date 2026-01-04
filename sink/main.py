
import sys
import os
import time
import threading
import argparse
from gi.repository import GLib

# Adicionar diretório pai ao path para importar 'common'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.bluez_classes import Advertisement, Application, Service, Characteristic
from common.ble_utils import BUS, SIC_SERVICE_UUID, SIC_RX_CHAR_UUID, get_device_object, get_gatt_characteristic
from common.pki_utils import read_nid_from_cert
from common.ble_agent import BLEAgent
from common.packet_structs import PacketHeader, MsgType
from common.crypto_utils import verify_mac
from common.security_handshake import SecurityHandshake
from common.ble_handshake_transport import handshake_receive_queue
from common.crl_manager import CRLManager
from sink.heartbeat_service import HeartbeatService
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

ADAPTER_PATH = "/org/bluez/hci0"

# UUIDs

class RealSecurity:
    """Real security module that signs data with Sink's private key."""
    
    def __init__(self, private_key_path):
        """Load Sink's private key for signing."""
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        print(f"[Security] Sink private key loaded: {private_key_path}")
    
    def sign_data(self, data):
        """Sign data with Sink's private key using ECDSA-SHA512."""
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA512())
        )
        return signature

class SinkConnectionManager:
    def __init__(self, sink_nid_bytes, cert_path, key_path, ca_cert_path, crl_manager=None):
        self.sink_nid = sink_nid_bytes
        self.advertisement = None
        self.bus = BUS
        self.crl_manager = crl_manager
        
        # Certificate paths for handshake
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        # Session keys for connected nodes (hop-by-hop)
        self.session_keys = {}  # mac -> session_key
        # Replay counters for connected nodes (hop-by-hop)
        self.replay_counters = {} # mac -> last_seen_sequence_number
        
        # DTLS
        from sink.dtls_server import DtlsServerManager
        self.dtls_manager = DtlsServerManager(sink_nid_bytes, cert_path, key_path, None)


        
        # Characteristic cache to avoid repeated lookups
        self.char_cache = {}  # mac -> characteristic proxy
        
        # Track which devices we've already checked for services
        self.services_checked = set()  # set of MACs





    def start_advertising(self):
        print("[Sink] A iniciar Advertisement (Hop Count=0)...")

        # If already advertising, unregister first to allow re-advertising
        # This is needed to remain discoverable after establishing connections
        if self.advertisement:
            try:
                print("[Sink] Unregistering existing advertisement...")
                self.advertisement.unregister(ADAPTER_PATH)
            except Exception as e:
                print(f"[Sink] Warning: Could not unregister existing advertisement: {e}")
            self.advertisement = None

        self.advertisement = Advertisement(
            self.bus,
            index=0,
            advertising_type='peripheral'
        )
        
        # Make Sink advertisement connectable
        self.advertisement.set_discoverable(True, 0)

        # NOTE: LocalName removed to stay within 31-byte BLE advertising limit
        # With manufacturer data (17 bytes) + overhead, we're at the limit

        # Manufacturer Data:
        # [ hop_count (1 byte) | sink_nid (N bytes) ]
        manuf_payload = bytes([0]) + self.sink_nid
        print(f"[DEBUG] Setting manufacturer data: ID=0xFFFE ({0xFFFE}), payload={manuf_payload.hex()} ({len(manuf_payload)} bytes)")
        self.advertisement.add_manufacturer_data(0xFFFE, manuf_payload)

        # REQUIRED FIX
        self.advertisement.register(ADAPTER_PATH)


    def broadcast_crl(self):
        """Broadcast CURRENT CRL to all connected nodes."""
        if not self.crl_manager:
            return

        revoked_list = self.crl_manager.get_revoked_list()
        # Even if empty, maybe we want to send it? But for now stick to previous logic.
        if not revoked_list:
            return 
            
        print(f"[Sink] Broadcasting CRL update ({len(revoked_list)} entries)...")
        
        try:
            import json
            payload = json.dumps({"type": "crl", "revoked": revoked_list}).encode('utf-8')
            
            # Send to all connected links individually with proper authentication
            # Iterate sessions directly, as we only want to send to authenticated nodes
            for mac, session_key in list(self.session_keys.items()):
                 self.send_authenticated_packet(mac, self.sink_nid, b'\xFF'*16, MsgType.CONTROL, payload)
            
        except Exception as e:
            print(f"[Sink] Error broadcasting CRL: {e}")

    def send_authenticated_packet(self, mac, src, dest, msg_type, payload):
        """Encapsulate payload with hop-by-hop security (MAC + Seq) and send."""
        if mac not in self.session_keys:
             print(f"[Sink] Cannot send auth packet to {mac}: No session key")
             return False
             
        key = self.session_keys[mac]
        
        # --- FIX: Garantir que a KEY é bytes ---
        if not isinstance(key, bytes):
            print(f"[Sink-Error] A chave de sessão para {mac} não é bytes! É {type(key)}")
            return False

        if not hasattr(self, 'out_counters'):
             self.out_counters = {}
             
        if mac not in self.out_counters:
             self.out_counters[mac] = 0
             
        self.out_counters[mac] += 1
        seq = self.out_counters[mac]
        
        # --- FIX: Garantir que o PAYLOAD é bytes ---
        if payload is None:
            payload = b''
        elif isinstance(payload, str):
            payload = payload.encode('utf-8')
        elif not isinstance(payload, bytes):
            # Tenta converter qualquer outra coisa (int, json object, etc)
            try:
                payload = bytes(payload)
            except:
                print(f"[Sink-Error] Payload inválido (não convertível para bytes): {type(payload)}")
                return False

        # 1. Pack with Zero MAC
        # O PacketHeader.pack deve retornar bytes. Se não retornar, temos problema no packet_structs.
        try:
            temp_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, b'\x00'*32)
            if not isinstance(temp_packet, bytes):
                temp_packet = bytes(temp_packet)
        except Exception as e:
            print(f"[Sink-Error] Falha no PacketHeader.pack: {e}")
            return False
        
        # 2. Calculate MAC
        try:
            from common.crypto_utils import generate_mac
            auth_mac = generate_mac(key, temp_packet)
        except Exception as e:
            print(f"[Sink-Error] Erro crítico ao gerar MAC (Key type: {type(key)}, Data type: {type(temp_packet)}): {e}")
            return False
        
        # 3. Final Pack
        final_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, auth_mac)
        
        # 4. Send
        self._send_packet(mac, list(final_packet))
        return True

    def _send_packet(self, mac, packet):
        # Lógica igual ao Node: obter char e escrever
        try:
            # Check if we have cached characteristic
            char_proxy = self.char_cache.get(mac)
            
            if not char_proxy:
                # First time sending to this device - check services
                if mac not in self.services_checked:
                    device = get_device_object(mac)
                    if device:
                        # Check if services are resolved
                        try:
                          
                            print(f"[Sink] Discovering services for {mac}...")
                            
                            # O handshake inicial precisa de mais tempo
                            for i in range(100): # Increased to 10s (100 * 0.1)
                                if device.ServicesResolved:
                                    print(f"[Sink] Services resolved for {mac}")
                                    break
                                

                                if get_gatt_characteristic(mac, SIC_RX_CHAR_UUID):
                                    print(f"[Sink] Found characteristic early for {mac}")
                                    break
                                
                                # Refresh object e esperar
                                import time
                                time.sleep(0.1)
                                device = get_device_object(mac)
                            # ----------------------------------------------------
                            
                        except:
                            pass  # Property might not exist
                    
                    self.services_checked.add(mac)
                
                # Try to get characteristic
                char_proxy = get_gatt_characteristic(mac, SIC_RX_CHAR_UUID)
                if char_proxy:
                    self.char_cache[mac] = char_proxy
                else:
                    # Don't spam - only log once per device
                    if mac not in self.char_cache:
                        print(f"[Sink] Failed to get characteristic for {mac}")
                    return
            
            # Send packet
            char_proxy.WriteValue(packet, {'type': GLib.Variant('s', 'command')})

        except Exception as e:
            err_str = str(e)
            print(f"[Sink] Erro ao enviar para {mac}: {e}")
            
            # If the characteristic is missing, it implies connection loss or state de-sync
            if "UnknownObject" in err_str or "doesn't exist" in err_str:
                 print(f"[Sink] Detectada perda de acesso GATT a {mac}. Assumindo desconexão.")
                 self._cleanup_connection(mac)
                 return

            # Check if device is still connected before cleaning up
            is_connected = False
            try:
                # Re-fetch device object to get latest state
                device = get_device_object(mac)
                if device and device.Connected:
                    is_connected = True
            except:
                pass

            if is_connected:
                 print(f"[Sink] Aviso: Erro de envio mas dispositivo {mac} ainda conectado. Mantendo sessão.")
                 # Clear cache just in case the characteristic object is stale
                 if mac in self.char_cache:
                     del self.char_cache[mac]
            else:
                 print(f"[Sink] Assumindo desconexão e limpando recursos...")
                 self._cleanup_connection(mac)
            pass # Ignorar outros erros (best effort)
    
    def perform_handshake(self, peer_mac):
        """
        Perform handshake as responder when a node connects.
        
        Args:
            peer_mac: MAC address of the connecting node
            
        Returns:
            bytes: 32-byte session key
        """
        print(f"[Sink-Handshake] Iniciando handshake com {peer_mac} (responder)")
        
        # Note: We can't use BLEHandshakeTransport here because Sink doesn't have
        # a BLEManager. Instead, we'll use the handshake_receive_queue directly
        # and send responses via _send_packet
        
        # For now, we'll create a simple transport wrapper
        from common.ble_handshake_transport import BLEHandshakeTransport
        
        class SinkHandshakeTransport:
            def __init__(self, mac, sink_conn_manager):
                self.mac = mac
                self.sink = sink_conn_manager
                self.receive_buffer = []
                self.timeout = 10.0
            
            def send(self, data):
                # Send via Sink's _send_packet
                MAX_CHUNK_SIZE = 100
                total_length = len(data)
                num_chunks = (total_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
                
                print(f"[Sink-Handshake-TX] Sending {total_length} bytes in {num_chunks} chunks")
                
                for i in range(num_chunks):
                    start = i * MAX_CHUNK_SIZE
                    end = min(start + MAX_CHUNK_SIZE, total_length)
                    chunk_data = data[start:end]
                    
                    frame = (
                        b'\xFF' +
                        total_length.to_bytes(4, 'big') +
                        i.to_bytes(2, 'big') +
                        chunk_data
                    )
                    
                    self.sink._send_packet(self.mac, list(frame))
                    time.sleep(0.15)
            
            def receive(self):
                import time
                print(f"[Sink-Handshake-RX] Waiting for data from {self.mac}")
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    if self.receive_buffer:
                        data = self._reassemble_chunks()
                        if data is not None:
                            print(f"[Sink-Handshake-RX] Received {len(data)} bytes")
                            return data
                    time.sleep(0.1)
                raise TimeoutError(f"Timeout waiting for data from {self.mac}")
            
            def _reassemble_chunks(self):
                if not self.receive_buffer:
                    return None
                chunks = sorted(self.receive_buffer, key=lambda x: x[1])
                total_length = chunks[0][0]
                expected_chunks = (total_length + 100 - 1) // 100
                if len(chunks) < expected_chunks:
                    return None
                data = b''.join(chunk[2] for chunk in chunks)
                self.receive_buffer = []
                return data[:total_length]
            
            def add_received_chunk(self, total_length, chunk_index, chunk_data):
                self.receive_buffer.append((total_length, chunk_index, chunk_data))
                print(f"[Sink-Handshake-RX] Received chunk {chunk_index}")
        
        transport = SinkHandshakeTransport(peer_mac, self)
        handshake_receive_queue.register_transport(peer_mac, transport)
        
        try:
            handshake = SecurityHandshake(self.cert_path, self.key_path, self.ca_cert_path, self.crl_manager)
            handshake.perform_handshake(transport)
            session_key = handshake.session_key
            
            if not session_key or len(session_key) != 32:
                raise RuntimeError("Invalid session key")
            
            # Store session key
            self.session_keys[peer_mac] = session_key



            print(f"[Sink-Handshake] Concluído com {peer_mac}: {session_key[:8].hex()}...")
            
            # Initialize replay counter for this new session
            self.replay_counters[peer_mac] = 0
            # Initialize outgoing counter
            if not hasattr(self, 'out_counters'):
                 self.out_counters = {}
            self.out_counters[peer_mac] = 0
            
            # Restart advertising to remain discoverable for other nodes
            # BlueZ stops advertising when a connection is established
            print(f"[Sink] Re-advertising to remain discoverable after connection...")
            self.start_advertising()
            
            return session_key
        finally:
            handshake_receive_queue.unregister_transport(peer_mac)


    def _cleanup_connection(self, mac):
        """Limpa todos os estados associados a um Node desconectado."""
        print(f"[Sink] A limpar conexão morta para {mac}...")

        # Limpar Cache BLE
        if mac in self.char_cache:
            del self.char_cache[mac]
        
        if mac in self.services_checked:
            self.services_checked.remove(mac)

        # Limpar Chaves de Sessão (Hop-by-Hop)
        if mac in self.session_keys:
            del self.session_keys[mac]
            print(f"[Sink] Chave de sessão removida para {mac}")

        if mac in self.replay_counters:
            del self.replay_counters[mac]


class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, conn_manager):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.conn_manager = conn_manager
        self.pending_handshakes = {}  # mac -> thread
        
    def WriteValue(self, value, options):
        val_bytes = bytes(value)
        print(f"[Sink-RX-RAW] WriteValue called with {len(val_bytes)} bytes", flush=True)
        
        # Extract MAC address
        mac = "unknown"
        device_path = options.get("device")
        if device_path and "dev_" in device_path:
            mac = device_path.split("dev_")[1].replace("_", ":")
        
        # Debug: Show first bytes
        print(f"[Sink-RX-DEBUG] {len(val_bytes)} bytes from {mac}, first 10 bytes: {val_bytes[:10].hex()}")
        
        # Check if this is handshake data (starts with 0xFF marker)
        if len(val_bytes) >= 7 and val_bytes[0] == 0xFF:
            try:
                total_length = int.from_bytes(val_bytes[1:5], 'big')
                chunk_index = int.from_bytes(val_bytes[5:7], 'big')
                chunk_data = val_bytes[7:]
                
                print(f"[Sink-RX-DEBUG] Detected handshake: total={total_length}, chunk={chunk_index}")
                
                # If this is the first chunk, start handshake in background FIRST
                # This registers the transport before we try to route the chunk
                # BUT only if we don't already have a session key or handshake in progress
                if (chunk_index == 0 and 
                    mac not in self.conn_manager.session_keys and
                    mac not in self.pending_handshakes and
                    not handshake_receive_queue.has_transport(mac)):
                    def run_handshake():
                        try:
                            self.conn_manager.perform_handshake(mac)
                        except Exception as e:
                            print(f"[!] Sink handshake failed with {mac}: {e}")
                        finally:
                            if mac in self.pending_handshakes:
                                del self.pending_handshakes[mac]
                    
                    print(f"[Sink-Handshake] Starting responder handshake with {mac}")
                    t = threading.Thread(target=run_handshake, daemon=True)
                    t.start()
                    self.pending_handshakes[mac] = t
                    
                    # Give the thread a moment to register the transport
                    import time
                    time.sleep(0.1)
                
                # Route to handshake queue
                if handshake_receive_queue.route_chunk(mac, total_length, chunk_index, chunk_data):
                    print(f"[Sink-RX-Handshake] Chunk {chunk_index} from {mac}")
                    return
                else:
                    print(f"[Sink-RX-DEBUG] Failed to route chunk {chunk_index} - no transport registered")
                    
            except Exception as e:
                print(f"[!] Error parsing handshake frame: {e}")
                import traceback
                traceback.print_exc()
        
        print(f"[Sink-RX] Recebidos {len(val_bytes)} bytes de {mac}")
        
        # --- Inbox Service Implementation ---
        try:
             # 1. Unpack Packet
            src_nid, dest_nid, msg_type, payload, seq_num, received_mac = PacketHeader.unpack(val_bytes)
            
            ## mecanismo de defesa erro de bytes
            if payload is None:
                payload = b''
            elif isinstance(payload, str):
                try:
                    payload = payload.encode('utf-8')
                except:
                    payload = b''
            elif not isinstance(payload, bytes):
                return # Ignora silenciosamente para não crashar


            # 2. Security Verification
            if mac not in self.conn_manager.session_keys:
                print(f"[!] Security Alert: Received packet from {mac} without active session")
                return

            session_key = self.conn_manager.session_keys[mac]
            
            # 2a. Replay Protection
            last_seq = self.conn_manager.replay_counters.get(mac, 0)
            if seq_num <= last_seq:
                print(f"[!] Security Alert: Replay detected from {mac} (Seq {seq_num} <= {last_seq})")
                return
            
            # 2b. Integrity Check (MAC)
            # Reconstruct packet header with zero MAC to verify
            check_packet = PacketHeader.pack(src_nid, dest_nid, msg_type, payload, seq_num, b'\x00'*32)
            
            if not verify_mac(session_key, check_packet, received_mac):
                print(f"[!] Security Alert: Invalid MAC from {mac}")
                return
            
            # Update sequence number
            self.conn_manager.replay_counters[mac] = seq_num
            
            if msg_type == MsgType.DTLS_HANDSHAKE:
                 # Handshake Packet (Unencrypted or Encrypted Handshake msg)
                 print(f"[Sink-RX] DTLS Packet from {src_nid.hex()[:8]}")
                 session = self.conn_manager.dtls_manager.get_or_create_session(src_nid)
                 
                 try:
                     # Attempt to decrypt if session expects encryption?
                     # Check Epoch in header
                     from common.dtls_structs import DtlsRecord, DtlsHandshakeMessage, DtlsHandshakeType, ContentType
                     ctype, epoch, seq, dtls_payload = DtlsRecord.unpack(payload)
                     
                     if epoch > 0:
                         # Encrypted (Finished message likely, or Re-handshake)
                         ctype, plaintext = session.decrypt(payload)
                         if ctype == ContentType.HANDSHAKE:
                             hs_type, _, _ = DtlsHandshakeMessage.unpack(plaintext)
                             if hs_type == DtlsHandshakeType.FINISHED:
                                 # Send Server Finished
                                 resp_record = session.handle_finished_and_reply(plaintext[12:], plaintext)
                                 # Send response
                                 print("[Sink] Sending Server Finished")
                                 self.conn_manager.send_authenticated_packet(mac, self.conn_manager.sink_nid, src_nid, MsgType.DTLS_HANDSHAKE, resp_record)
                                 
                     else:
                         # Unencrypted (ClientHello, ClientKeyExchange)
                         if ctype == ContentType.HANDSHAKE:
                             hs_type, _, _ = DtlsHandshakeMessage.unpack(dtls_payload)
                             
                             if hs_type == DtlsHandshakeType.CLIENT_HELLO:
                                 resp_record = session.handle_client_hello(dtls_payload[12:], dtls_payload)
                                 print("[Sink] Sending ServerHello")
                                 self.conn_manager.send_authenticated_packet(mac, self.conn_manager.sink_nid, src_nid, MsgType.DTLS_HANDSHAKE, resp_record)
                                 
                             elif hs_type == DtlsHandshakeType.CLIENT_KEY_EXCHANGE:
                                 session.handle_client_key_exchange(dtls_payload[12:], dtls_payload)
                                 # No immediate response, waiting for Finished
                 
                 except Exception as e:
                     print(f"[Sink] DTLS Error: {e}")
                     import traceback
                     traceback.print_exc()

            elif msg_type == MsgType.DATA:
                # App Data (Encrypted)
                session = self.conn_manager.dtls_manager.get_session(src_nid)
                if session and session.established:
                    try:
                        from common.dtls_structs import ContentType
                        ctype, plaintext = session.decrypt(payload)
                        if ctype == ContentType.APPLICATION_DATA:
                             message_text = plaintext.decode('utf-8')
                             print(f"\n{'='*40}")
                             print(f"INBOX MESSAGE (DTLS SECURED)")
                             print(f"FROM: {src_nid.hex()[:8]}")
                             print(f"TEXT: {message_text}")
                             print(f"{'='*40}\n")
                    except Exception as e:
                        print(f"[Sink] Decrypt Error: {e}")
                else:
                    # Legacy / Plaintext
                    try:
                        message_text = payload.decode('utf-8')
                        print(f"[RX-PLAIN] {message_text}")
                    except:
                        pass
                # Regular unencrypted data (legacy)
                try:
                    message_text = payload.decode('utf-8')
                    print(f"\n{'='*40}")
                    print(f"INBOX MESSAGE START")
                    print(f"FROM: Node {src_nid.hex()[:8]}...")
                    print(f"TEXT: {message_text}")
                    print(f"SEQ: {seq_num}")
                    print(f"{'='*40}\n")
                except UnicodeDecodeError:
                    print(f"[Inbox] Received binary payload from {src_nid.hex()}: {payload.hex()}")
            
            elif msg_type == MsgType.HEARTBEAT:
                # Sink usually sends heartbeats, but if nodes send them back for some reason:
                print(f"[Rx] Heartbeat received from {src_nid.hex()}")
                
            else:
                print(f"[Rx] Unknown message type {msg_type} from {src_nid.hex()}")

        except Exception as e:
            print(f"[!] Error processing packet from {mac}: {e}")
            import traceback
            traceback.print_exc()

class SinkApplication(Application):
    def __init__(self, bus, conn_manager):
        super().__init__(bus)
        self.service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(self.service)
        self.char = RxCharacteristic(bus, 0, self.service, conn_manager)
        self.service.add_characteristic(self.char)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/sink.crt", help="Caminho para o certificado do Sink")
    parser.add_argument("--key", default="certs/sink.key", help="Caminho para a chave privada do Sink")
    parser.add_argument("--ca", default="certs/ca.crt", help="Caminho para o certificado CA")
    args = parser.parse_args()
    
    sink_nid = read_nid_from_cert(args.cert)
    if not sink_nid:
        sys.exit(1)
    
    # Verify files exist
    for path in [args.cert, args.key, args.ca]:
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            sys.exit(1)
        
    print(f"[Sink] NID carregado: {sink_nid.hex()}")
    
    # 1. D-Bus Loop
    loop = GLib.MainLoop()
    t_glib = threading.Thread(target=loop.run)
    t_glib.daemon = True
    t_glib.start()
    
    # 2. Managers
    crl_manager = CRLManager("crl.json")
    conn_manager = SinkConnectionManager(sink_nid, args.cert, args.key, args.ca, crl_manager)
    security = RealSecurity(args.key)
    
    # 3. Heartbeat Service
    hb_service = HeartbeatService(sink_nid, conn_manager, security)
    
    # 4. GATT Server (Receive Data)
    app = SinkApplication(BUS, conn_manager)
    app.register()
    
    # DISABLED: BLE Agent causes unwanted BR/EDR connections that kill LE when they fail
    # Initialize and register BLE  for pairing
    # agent = BLEAgent(BUS)
    # agent.register()
    
    # Start
    conn_manager.start_advertising()
    hb_service.start()
    
    # 5. CRL Broadcast Service (Periodic)
    def crl_broadcast_loop():
        while True:
            time.sleep(30) # Broadcast every 30 seconds
            conn_manager.broadcast_crl()
            
    t_crl = threading.Thread(target=crl_broadcast_loop, daemon=True)
    t_crl.start()
    
    print("[Sink] Sink a correr. Pressione Ctrl+C para sair.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Sink] A encerrar...")
        hb_service.stop()
        loop.quit()

if __name__ == "__main__":
    main()
