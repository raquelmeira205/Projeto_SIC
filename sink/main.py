
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
from common.security_handshake import SecurityHandshake
from common.ble_handshake_transport import handshake_receive_queue
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
    def __init__(self, sink_nid_bytes, cert_path, key_path, ca_cert_path):
        self.sink_nid = sink_nid_bytes
        self.advertisement = None
        self.bus = BUS
        
        # Certificate paths for handshake
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        # Session keys for connected nodes
        self.session_keys = {}  # mac -> session_key

    def start_advertising(self):
        print("[Sink] A iniciar Advertisement (Hop Count=0)...")

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

    def send_to_all_links(self, packet):
        # Enviar para todos os dispositivos conectados que exponham o serviço SIC
        # 1. Obter dispositivos conectados
        # Iterar ObjectManager da BlueZ
        try:
            obj_manager = self.bus.get("org.bluez", "/")
            objects = obj_manager.GetManagedObjects()
            
            for path, interfaces in objects.items():
                if "org.bluez.Device1" in interfaces:
                    props = interfaces["org.bluez.Device1"]
                    if props.get("Connected", False):
                        mac = props.get("Address")
                        # Tentar enviar
                        self._send_packet(mac, packet)
                        
        except Exception as e:
            print(f"[Sink] Erro ao enviar heartbeats: {e}")

    def _send_packet(self, mac, packet):
        # Lógica igual ao Node: obter char e escrever
        try:
            char_proxy = get_gatt_characteristic(mac, SIC_RX_CHAR_UUID)
            if char_proxy:
                char_proxy.WriteValue(packet, {'type': GLib.Variant('s', 'command')})
                # print(f"[Sink] Enviado para {mac}")
        except Exception as e:
            pass # Ignorar falhas de envio (best effort)
    
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
                MAX_CHUNK_SIZE = 480
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
                    time.sleep(0.05)
            
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
                expected_chunks = (total_length + 480 - 1) // 480
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
            handshake = SecurityHandshake(self.cert_path, self.key_path, self.ca_cert_path)
            handshake.perform_handshake(transport)
            session_key = handshake.session_key
            
            if not session_key or len(session_key) != 32:
                raise RuntimeError("Invalid session key")
            
            # Store session key
            self.session_keys[peer_mac] = session_key
            print(f"[Sink-Handshake] Concluído com {peer_mac}: {session_key[:8].hex()}...")
            
            return session_key
        finally:
            handshake_receive_queue.unregister_transport(peer_mac)

class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, conn_manager):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.conn_manager = conn_manager
        self.pending_handshakes = {}  # mac -> thread
        
    def WriteValue(self, value, options):
        val_bytes = bytes(value)
        
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
                if chunk_index == 0 and mac not in self.pending_handshakes:
                    def run_handshake():
                        try:
                            self.conn_manager.perform_handshake(mac)
                        except Exception as e:
                            print(f"[!] Sink handshake failed with {mac}: {e}")
                        finally:
                            if mac in self.pending_handshakes:
                                del self.pending_handshakes[mac]
                    
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
        # Aqui processaria os dados recebidos dos nós
        # Ex: parse packet, log, store database...

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
    conn_manager = SinkConnectionManager(sink_nid, args.cert, args.key, args.ca)
    security = RealSecurity(args.key)
    
    # 3. Heartbeat Service
    hb_service = HeartbeatService(sink_nid, conn_manager, security)
    
    # 4. GATT Server (Receive Data)
    app = SinkApplication(BUS, conn_manager)
    app.register()
    
    # Start
    conn_manager.start_advertising()
    hb_service.start()
    
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
