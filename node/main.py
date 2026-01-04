import sys
import os
import threading
import time
import argparse
from gi.repository import GLib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.bluez_classes import Application, Service, Characteristic
from common.ble_utils import BUS, SIC_SERVICE_UUID, SIC_RX_CHAR_UUID
from common.pki_utils import read_nid_from_cert
from common.ble_handshake_transport import handshake_receive_queue
from common.ble_agent import BLEAgent
from node.ble_manager import BLEManager
from node.router import Router
from node.cli_ui import NodeCLI
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class RealSecurity:
    """Real security module that verifies Sink signatures."""
    
    def __init__(self, sink_cert_path):
        """Load Sink certificate for signature verification."""
        with open(sink_cert_path, 'rb') as f:
            self.sink_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        self.sink_public_key = self.sink_cert.public_key()
        print(f"[Security] Sink certificate loaded: {sink_cert_path}")
    
    def verify_sink_signature(self, data, signature):
        """Verify signature from Sink using its public key."""
        try:
            self.sink_public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA512())
            )
            return True
        except Exception as e:
            print(f"[!] Signature verification failed: {e}")
            return False


class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, router):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write', 'write-without-response'], service)
        self.router = router

    def WriteValue(self, value, options):
        data = bytes(value)
        mac = "unknown"

        device_path = options.get("device")
        if device_path and "dev_" in device_path:
            mac = device_path.split("dev_")[1].replace("_", ":")

        # DEBUG: Show first bytes to diagnose handshake detection issue
        print(f"[RX-DEBUG] {len(data)} bytes from {mac}, first 10 bytes: {data[:10].hex()}")

        # Check if this is handshake data (starts with 0xFF marker)
        if len(data) >= 7 and data[0] == 0xFF:
            try:
                total_length = int.from_bytes(data[1:5], 'big')
                chunk_index = int.from_bytes(data[5:7], 'big')
                chunk_data = data[7:]
                
                print(f"[RX-Handshake] Chunk {chunk_index} from {mac}")
                
                # If this is the first chunk from an unknown MAC, trigger incoming handshake FIRST
                # This will register the transport so route_chunk will work
                if (chunk_index == 0 and 
                    mac not in self.router.link_keys and 
                    not handshake_receive_queue.has_transport(mac)):
                    print(f"[RX-Handshake] First chunk from unknown peer {mac}, triggering handshake response")
                    self.router.handle_incoming_handshake(mac)
                    # Give thread time to register transport
                    import time
                    time.sleep(0.1)
                
                # Now route the chunk (transport should be registered by now)
                if handshake_receive_queue.route_chunk(mac, total_length, chunk_index, chunk_data):
                    return
                else:
                    print(f"[!] Warning: Could not route handshake chunk {chunk_index} from {mac}")
                    return
                    
            except Exception as e:
                print(f"[!] Error parsing handshake frame: {e}")
                pass  # Not handshake data, process normally
        
        print(f"[RX] {len(data)} bytes de {mac}")
        self.router.process_incoming_packet(data, mac)


class NodeApplication(Application):
    def __init__(self, bus, router):
        super().__init__(bus)
        service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(service)

        char = RxCharacteristic(bus, 0, service, router)
        service.add_characteristic(char)
        
        self.router = router

    def receive(self, src_nid, payload):
        print(f"[App] Recebido de {src_nid.hex()}: {payload}")
        # Store in router stats for UI (or Node)
        # Assuming payload is text bytes
        try:
            msg_text = payload.decode('utf-8')
        except:
             msg_text = payload.hex()
             
        self.router.stats["received_messages"].append((src_nid.hex(), msg_text))


class Node:
    def __init__(self, nid, cert_path, key_path, ca_cert_path, sink_cert_path):
        print(f"[*] Node iniciado: {nid.hex()}")

        # Guardar o NID também no Node para a UI
        self.node_nid = nid  

        self.ble_manager = BLEManager(nid)
        self.security = RealSecurity(sink_cert_path)
        self.router = Router(
            nid, 
            self.security, 
            self.ble_manager,
            cert_path=cert_path,
            key_path=key_path,
            ca_cert_path=ca_cert_path
        )

        self.ble_manager.set_router_callbacks(
            self.router.set_uplink,
            self.router.handle_disconnection
        )

        self.app = NodeApplication(BUS, self.router)
        self.router.app_layer = self.app # Link app layer
        self.app.register()

        # Initialize and register BLE Agent for pairing
        self.agent = BLEAgent(BUS)
        self.agent.register()

        time.sleep(0.5)
        self.ble_manager.start_advertising()

        self.running = True

    def start_logic_loop(self):
        t = threading.Thread(target=self._logic_loop, daemon=True)
        t.start()

    def _logic_loop(self):
        time.sleep(2)
        while self.running:
            self.ble_manager.monitor_connection_status()
            # Manual mode: no automatic uplink search
            time.sleep(10)
    
    def scan_for_uplinks(self):
        """Manually trigger BLE scan for nearby devices"""
        print("[*] Manual scan triggered")
        return self.ble_manager.scan_for_devices()

    def send_to_sink(self, text):
        if not self.router.sink_nid:
            print("[!] Sink NID desconhecido")
            return False
            
        return self.router.send_app_data(self.router.sink_nid, text.encode('utf-8'))

    def force_connect(self, mac):
        print(f"[*] Force Connect solicitado para {mac}")
        
        # 1. Disconnect current Uplink if exists
        curr = self.ble_manager.uplink_addr
        if curr:
             print(f"[*] A desconectar do uplink atual: {curr}")
             self.ble_manager.disconnect_from_device(curr)
        
        # 2. Attempt Connection
        if self.ble_manager.connect_to_device(mac):
             print(f"[*] Sucesso Conexão Forçada a {mac}")
             
             # 3. Manually set as Uplink
             # We might not know NID or Hop Count yet.
             # Hop Count = 255 (Unknown/High)
             self.ble_manager.uplink_addr = mac
             self.ble_manager.uplink_nid = b'\x00'*16 # Unknown
             self.ble_manager.hop_count = 255
             self.ble_manager.update_advertisement()
             
             # Notify Router
             self.router.set_uplink(mac, 254) # results in local hop=255
             
             return True
        else:
             print(f"[!] Falha Conexão Forçada a {mac}")
             return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/nodeA.crt", help="Node certificate path")
    parser.add_argument("--key", default="certs/nodeA.key", help="Node private key path")
    parser.add_argument("--ca", default="certs/ca.crt", help="CA certificate path")
    parser.add_argument("--sink-cert", default="certs/sink.crt", help="Sink certificate path")
    args = parser.parse_args()

    nid = read_nid_from_cert(args.cert)
    if not nid:
        sys.exit(1)
    
    # Verify all certificate files exist
    for path in [args.cert, args.key, args.ca, args.sink_cert]:
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            sys.exit(1)

    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True).start()

    node = Node(nid, args.cert, args.key, args.ca, args.sink_cert)
    node.start_logic_loop()

    # Start CLI interface
    cli = NodeCLI(node)
    
    try:
        cli.start()
    finally:
        node.running = False
        loop.quit()


if __name__ == "__main__":
    main()
