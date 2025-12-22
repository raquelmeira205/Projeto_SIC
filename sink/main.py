
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
from common.packet_structs import PacketHeader, MsgType, NID_SIZE
from common.crypto_utils import verify_mac
from sink.heartbeat_service import HeartbeatService
import queue

ADAPTER_PATH = "/org/bluez/hci0"

# UUIDs

# UUIDs


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

        # Optional but useful for debugging
        # Shortened name to fit 31-byte limit:
        # Flags(3) + Manuf(21) + Name(6) = 30 bytes.
        # self.advertisement.add_local_name("Sink")
        
        # Manufacturer Data:
        # [ hop_count (1 byte) | sink_nid (N bytes) ]
        manuf_payload = bytes([0]) + self.sink_nid
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
    def __init__(self, bus, index, service, callback):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.callback = callback
        
    def WriteValue(self, value, options):
        val_bytes = bytes(value)
        sender = "unknown"
        if "device" in options:
             dev_path = options["device"]
             # /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX
             parts = dev_path.split('_')
             if len(parts) >= 6:
                 sender = ":".join(parts[-6:])
                 
        if self.callback:
            self.callback(val_bytes, sender)

class SinkApplication(Application):
    def __init__(self, bus, recv_callback):
        super().__init__(bus)
        self.service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(self.service)
        self.char = RxCharacteristic(bus, 0, self.service, recv_callback)
        self.service.add_characteristic(self.char)

from sink.sink_logic import SinkLogic

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/sink.crt", help="Caminho para o certificado do Sink")
    parser.add_argument("--key", default="certs/sink.key", help="Caminho para chave privada")
    parser.add_argument("--ca", default="certs/ca.crt")
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
    
    # 2. Logic & Security
    logic = SinkLogic(sink_nid, args.cert, args.key, args.ca)
    
    # 3. GATT Server (Receive Data) -> Connect callback to Logic
    app = SinkApplication(BUS, logic.on_packet_received)
    app.register()
    
    # 4. Connection Manager (Advertisement)
    conn_manager = SinkConnectionManager(sink_nid)
    conn_manager.start_advertising()
    
    # 5. Heartbeat Service (Optional integration with logic?)
    # For now keep it separate or logic can access it?
    # security = MockSecurity() # Deprecated?
    # hb_service = HeartbeatService(sink_nid, conn_manager, security)
    # hb_service.start()
    
    print("[Sink] Sink seguro a correr. Aguardando conexões...")
    
    try:
        while True:
            time.sleep(5)
            print("[Sink] Alive... (Advertising)")
    except KeyboardInterrupt:
        print("\n[Sink] A encerrar...")
        # hb_service.stop()
        loop.quit()

if __name__ == "__main__":
    main()
