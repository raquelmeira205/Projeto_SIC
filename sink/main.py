
import sys
import os
import time
import threading
import argparse
from gi.repository import GLib

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
from sink.rate_limiter import RateLimiter

ADAPTER_PATH = "/org/bluez/hci0"


class RealSecurity:
    """Módulo de segurança real que assina dados com a chave privada do Sink."""
    
    def __init__(self, private_key_path):
        """
        Carrega a chave privada para assinatura.
        
        :param private_key_path: Caminho para a chave privada do Sink.
        """
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        print(f"[Security] Sink private key loaded: {private_key_path}")
    
    def sign_data(self, data):
        """
        Assina os dados usando ECDSA-SHA512.
        
        :param data: Dados a serem assinados.
        :return: Assinatura digital.
        """
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA512())
        )
        return signature

class SinkConnectionManager:
    """
    Gerencia as conexões BLE, segurança e sessões do Sink.
    Controla o advertisement, handshakes e roteamento de mensagens para as sessões DTLS.
    """
    
    def __init__(self, sink_nid_bytes, cert_path, key_path, ca_cert_path, crl_manager=None):
        self.sink_nid = sink_nid_bytes
        self.advertisement = None
        self.bus = BUS
        self.crl_manager = crl_manager
        
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        self.session_keys = {}  # mac -> session_key
        self.replay_counters = {} # mac -> last_seen_sequence_number
        
        from sink.dtls_server import DtlsServerManager
        self.dtls_manager = DtlsServerManager(sink_nid_bytes, cert_path, key_path, None)
        
        self.rate_limiter = RateLimiter()
        
        self.char_cache = {}  # mac -> characteristic proxy
        self.services_checked = set()

    def start_advertising(self):
        """Inicia a publicidade BLE do Sink (Hop Count = 0)."""
        print("[Sink] A iniciar Advertisement (Hop Count=0)...")

        if self.advertisement:
            try:
                self.advertisement.unregister(ADAPTER_PATH)
            except Exception:
                pass
            self.advertisement = None

        self.advertisement = Advertisement(
            self.bus,
            index=0,
            advertising_type='peripheral'
        )
        
        self.advertisement.set_discoverable(True, 0)

        # Manufacturer Data: [ hop_count (1 byte) | sink_nid (16 bytes) ]
        manuf_payload = bytes([0]) + self.sink_nid
        self.advertisement.add_manufacturer_data(0xFFFE, manuf_payload)

        self.advertisement.register(ADAPTER_PATH)

    def broadcast_crl(self):
        """Transmite a CRL atual para todos os nós conectados."""
        if not self.crl_manager:
            return

        revoked_list = self.crl_manager.get_revoked_list()
        if not revoked_list:
            return 
            
        print(f"[Sink] Broadcasting CRL update ({len(revoked_list)} entries)...")
        
        try:
            import json
            payload = json.dumps({"type": "crl", "revoked": revoked_list}).encode('utf-8')
            
            for mac, session_key in list(self.session_keys.items()):
                 self.send_authenticated_packet(mac, self.sink_nid, b'\xFF'*16, MsgType.CONTROL, payload)
            
        except Exception as e:
            print(f"[Sink] Error broadcasting CRL: {e}")

    def send_authenticated_packet(self, mac, src, dest, msg_type, payload):
        """
        Empacota e envia um pacote autenticado (Hop-by-Hop).
        
        :param mac: MAC do destino imediato (Próximo salto).
        :param src: NID de origem.
        :param dest: NID de destino.
        :param msg_type: Tipo da mensagem.
        :param payload: Dados da mensagem.
        :return: True se enviado com sucesso, False caso contrário.
        """
        if mac not in self.session_keys:
             return False
             
        key = self.session_keys[mac]
        
        if not isinstance(key, bytes):
            return False

        if not hasattr(self, 'out_counters'):
             self.out_counters = {}
             
        if mac not in self.out_counters:
             self.out_counters[mac] = 0
             
        self.out_counters[mac] += 1
        seq = self.out_counters[mac]
        
        if payload is None:
            payload = b''
        elif isinstance(payload, str):
            payload = payload.encode('utf-8')
        elif not isinstance(payload, bytes):
            try:
                payload = bytes(payload)
            except:
                return False

        try:
            temp_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, b'\x00'*32)
            if not isinstance(temp_packet, bytes):
                temp_packet = bytes(temp_packet)
        except Exception:
            return False
        
        try:
            from common.crypto_utils import generate_mac
            auth_mac = generate_mac(key, temp_packet)
        except Exception:
            return False
        
        final_packet = PacketHeader.pack(src, dest, msg_type, payload, seq, auth_mac)
        
        self._send_packet(mac, list(final_packet))
        return True

    def _send_packet(self, mac, packet):
        """Envia pacote via GATT Write."""
        try:
            char_proxy = self.char_cache.get(mac)
            
            if not char_proxy:
                if mac not in self.services_checked:
                    device = get_device_object(mac)
                    if device:
                        try:
                            # Tenta descobrir serviços
                            for i in range(100):
                                if device.ServicesResolved:
                                    break
                                
                                if get_gatt_characteristic(mac, SIC_RX_CHAR_UUID):
                                    break
                                
                                import time
                                time.sleep(0.1)
                                device = get_device_object(mac)
                        except:
                            pass
                    
                    self.services_checked.add(mac)
                
                char_proxy = get_gatt_characteristic(mac, SIC_RX_CHAR_UUID)
                if char_proxy:
                    self.char_cache[mac] = char_proxy
                else:
                    return
            
            char_proxy.WriteValue(packet, {'type': GLib.Variant('s', 'command')})

        except Exception as e:
            err_str = str(e)
            
            if "UnknownObject" in err_str or "doesn't exist" in err_str:
                 self._cleanup_connection(mac)
                 return

            is_connected = False
            try:
                device = get_device_object(mac)
                if device and device.Connected:
                    is_connected = True
            except:
                pass

            if is_connected:
                 if mac in self.char_cache:
                     del self.char_cache[mac]
            else:
                 self._cleanup_connection(mac)
    
    def perform_handshake(self, peer_mac):
        """
        Realiza o handshake como respondedor.
        
        :param peer_mac: MAC do nó conectado.
        :return: Chave de sessão derivada.
        """
        print(f"[Sink-Handshake] Iniciando handshake com {peer_mac} (responder)")
        
        from common.ble_handshake_transport import BLEHandshakeTransport
        
        class SinkHandshakeTransport:
            def __init__(self, mac, sink_conn_manager):
                self.mac = mac
                self.sink = sink_conn_manager
                self.receive_buffer = []
                self.timeout = 10.0
            
            def send(self, data):
                MAX_CHUNK_SIZE = 100
                total_length = len(data)
                num_chunks = (total_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
                
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
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    if self.receive_buffer:
                        data = self._reassemble_chunks()
                        if data is not None:
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
        
        transport = SinkHandshakeTransport(peer_mac, self)
        handshake_receive_queue.register_transport(peer_mac, transport)
        
        try:
            handshake = SecurityHandshake(self.cert_path, self.key_path, self.ca_cert_path, self.crl_manager)
            handshake.perform_handshake(transport)
            session_key = handshake.session_key
            
            if not session_key or len(session_key) != 32:
                raise RuntimeError("Invalid session key")
            
            self.session_keys[peer_mac] = session_key
            self.replay_counters[peer_mac] = 0
            
            if not hasattr(self, 'out_counters'):
                 self.out_counters = {}
            self.out_counters[peer_mac] = 0
            
            self.start_advertising()
            
            return session_key
        finally:
            handshake_receive_queue.unregister_transport(peer_mac)

    def _cleanup_connection(self, mac):
        """Limpa recursos de uma conexão encerrada."""
        if mac in self.char_cache:
            del self.char_cache[mac]
        
        if mac in self.services_checked:
            self.services_checked.remove(mac)

        if mac in self.session_keys:
            del self.session_keys[mac]

        if mac in self.replay_counters:
            del self.replay_counters[mac]


class RxCharacteristic(Characteristic):
    """
    Característica GATT de Recepção no Sink.
    Recebe dados dos nós, gerencia handshakes e processa mensagens.
    """
    
    def __init__(self, bus, index, service, conn_manager):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.conn_manager = conn_manager
        self.pending_handshakes = {}
        
    def WriteValue(self, value, options):
        val_bytes = bytes(value)
        
        mac = "unknown"
        device_path = options.get("device")
        if device_path and "dev_" in device_path:
            mac = device_path.split("dev_")[1].replace("_", ":")
        
        # Detecção de Handshake (Marcador 0xFF)
        if len(val_bytes) >= 7 and val_bytes[0] == 0xFF:
            try:
                total_length = int.from_bytes(val_bytes[1:5], 'big')
                chunk_index = int.from_bytes(val_bytes[5:7], 'big')
                chunk_data = val_bytes[7:]
                
                if (chunk_index == 0 and 
                    mac not in self.conn_manager.session_keys and
                    mac not in self.pending_handshakes and
                    not handshake_receive_queue.has_transport(mac)):
                    
                    def run_handshake():
                        try:
                            self.conn_manager.perform_handshake(mac)
                        except Exception as e:
                            print(f"[!] Sink handshake falhou com {mac}: {e}")
                        finally:
                            if mac in self.pending_handshakes:
                                del self.pending_handshakes[mac]
                    
                    t = threading.Thread(target=run_handshake, daemon=True)
                    t.start()
                    self.pending_handshakes[mac] = t
                    
                    import time
                    time.sleep(0.1)
                
                if handshake_receive_queue.route_chunk(mac, total_length, chunk_index, chunk_data):
                    return
                else:
                    return
                    
            except Exception:
                pass
        
        # Processamento de Pacotes Normais
        try:
            src_nid, dest_nid, msg_type, payload, seq_num, received_mac = PacketHeader.unpack(val_bytes)
            
            if payload is None:
                payload = b''
            elif isinstance(payload, str):
                try:
                    payload = payload.encode('utf-8')
                except:
                    payload = b''
            elif not isinstance(payload, bytes):
                return


            if mac not in self.conn_manager.session_keys:
                return

            session_key = self.conn_manager.session_keys[mac]
            
            last_seq = self.conn_manager.replay_counters.get(mac, 0)
            if seq_num <= last_seq:
                return
            
            check_packet = PacketHeader.pack(src_nid, dest_nid, msg_type, payload, seq_num, b'\x00'*32)
            
            if not verify_mac(session_key, check_packet, received_mac):
                print(f"[!] Security Alert: MAC Inválido de {mac}")
                return
            
            self.conn_manager.replay_counters[mac] = seq_num
            
            if not self.conn_manager.rate_limiter.check_rate_limit(src_nid, msg_type):
                 print(f"[Sink] Rate Limit Excedido para Nó {src_nid.hex()[:8]}")
                 return
            
            if msg_type == MsgType.DTLS_HANDSHAKE:
                 session = self.conn_manager.dtls_manager.get_or_create_session(src_nid)
                 
                 try:
                     from common.dtls_structs import DtlsRecord, DtlsHandshakeMessage, DtlsHandshakeType, ContentType
                     ctype, epoch, seq, dtls_payload = DtlsRecord.unpack(payload)
                     
                     if epoch > 0:
                         ctype, plaintext = session.decrypt(payload)
                         if ctype == ContentType.HANDSHAKE:
                             hs_type, _, _ = DtlsHandshakeMessage.unpack(plaintext)
                             if hs_type == DtlsHandshakeType.FINISHED:
                                 resp_record = session.handle_finished_and_reply(plaintext[12:], plaintext)
                                 self.conn_manager.send_authenticated_packet(mac, self.conn_manager.sink_nid, src_nid, MsgType.DTLS_HANDSHAKE, resp_record)
                                 
                     else:
                         if ctype == ContentType.HANDSHAKE:
                             hs_type, _, _ = DtlsHandshakeMessage.unpack(dtls_payload)
                             
                             if hs_type == DtlsHandshakeType.CLIENT_HELLO:
                                 resp_record = session.handle_client_hello(dtls_payload[12:], dtls_payload)
                                 self.conn_manager.send_authenticated_packet(mac, self.conn_manager.sink_nid, src_nid, MsgType.DTLS_HANDSHAKE, resp_record)
                                 
                             elif hs_type == DtlsHandshakeType.CLIENT_KEY_EXCHANGE:
                                 session.handle_client_key_exchange(dtls_payload[12:], dtls_payload)
                 
                 except Exception as e:
                     print(f"[Sink] Erro DTLS: {e}")
                     import traceback
                     traceback.print_exc()

            elif msg_type == MsgType.DATA:
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
                        print(f"[Sink] Erro Decifragem: {e}")
                else:
                    try:
                        message_text = payload.decode('utf-8')
                        print(f"\n{'='*40}")
                        print(f"INBOX MESSAGE START")
                        print(f"FROM: Node {src_nid.hex()[:8]}...")
                        print(f"TEXT: {message_text}")
                        print(f"SEQ: {seq_num}")
                        print(f"{'='*40}\n")
                    except Exception:
                        pass
            
            elif msg_type == MsgType.HEARTBEAT:
                pass
                
        except Exception as e:
            print(f"[!] Erro processamento pacote de {mac}: {e}")

class SinkApplication(Application):
    """Aplicação principal do Sink (Serviço GATT)."""
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
    
    for path in [args.cert, args.key, args.ca]:
        if not os.path.exists(path):
            print(f"[!] Arquivo não encontrado: {path}")
            sys.exit(1)
        
    print(f"[Sink] NID carregado: {sink_nid.hex()}")
    
    loop = GLib.MainLoop()
    t_glib = threading.Thread(target=loop.run)
    t_glib.daemon = True
    t_glib.start()
    
    crl_manager = CRLManager("crl.json")
    conn_manager = SinkConnectionManager(sink_nid, args.cert, args.key, args.ca, crl_manager)
    security = RealSecurity(args.key)
    
    hb_service = HeartbeatService(sink_nid, conn_manager, security)
    
    app = SinkApplication(BUS, conn_manager)
    app.register()
    
    agent = BLEAgent(BUS)
    agent.register()
    
    conn_manager.start_advertising()
    hb_service.start()
    
    def crl_broadcast_loop():
        while True:
            time.sleep(30)
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
