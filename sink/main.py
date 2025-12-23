
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
    def __init__(self, sink_nid_bytes):
        self.sink_nid = sink_nid_bytes
        self.advertisement = None
        self.bus = BUS

    def start_advertising(self):
        print("[Sink] A iniciar Advertisement (Hop Count=0)...")

        self.advertisement = Advertisement(
            self.bus,
            index=0,
            advertising_type='peripheral'
        )

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

class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        
    def WriteValue(self, value, options):
        val_bytes = bytes(value)
        print(f"[Sink-RX] Recebidos {len(val_bytes)} bytes. (Dados do Sensor?)")
        # Aqui processaria os dados recebidos dos nós
        # Ex: parse packet, log, store database...

class SinkApplication(Application):
    def __init__(self, bus):
        super().__init__(bus)
        self.service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(self.service)
        self.char = RxCharacteristic(bus, 0, self.service)
        self.service.add_characteristic(self.char)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/sink.crt", help="Caminho para o certificado do Sink")
    parser.add_argument("--key", default="certs/sink.key", help="Caminho para a chave privada do Sink")
    args = parser.parse_args()
    
    sink_nid = read_nid_from_cert(args.cert)
    if not sink_nid:
        sys.exit(1)
    
    # Verify key file exists
    if not os.path.exists(args.key):
        print(f"[!] Private key file not found: {args.key}")
        sys.exit(1)
        
    print(f"[Sink] NID carregado: {sink_nid.hex()}")
    
    # 1. D-Bus Loop
    loop = GLib.MainLoop()
    t_glib = threading.Thread(target=loop.run)
    t_glib.daemon = True
    t_glib.start()
    
    # 2. Managers
    conn_manager = SinkConnectionManager(sink_nid)
    security = RealSecurity(args.key)
    
    # 3. Heartbeat Service
    hb_service = HeartbeatService(sink_nid, conn_manager, security)
    
    # 4. GATT Server (Receive Data)
    app = SinkApplication(BUS)
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
