
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

ADAPTER_PATH = "/org/bluez/hci0"

# UUIDs

class MockSecurity:
    def sign_data(self, data):
        return b"mock_signature_123" # 16+ bytes?

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
    args = parser.parse_args()
    
    sink_nid = read_nid_from_cert(args.cert)
    if not sink_nid:
        sys.exit(1)
        
    print(f"[Sink] NID carregado: {sink_nid.hex()}")
    
    # 1. D-Bus Loop
    loop = GLib.MainLoop()
    t_glib = threading.Thread(target=loop.run)
    t_glib.daemon = True
    t_glib.start()
    
    # 2. Managers
    conn_manager = SinkConnectionManager(sink_nid)
    security = MockSecurity()
    
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
