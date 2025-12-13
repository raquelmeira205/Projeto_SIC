
import sys
import threading
import time
import argparse
import tkinter as tk
from gi.repository import GLib

from common.bluez_classes import Application, Service, Characteristic
from common.ble_utils import BUS, SIC_SERVICE_UUID, SIC_RX_CHAR_UUID
from common.pki_utils import read_nid_from_cert
from node.ble_manager import BLEManager
from node.router import Router
from node.ui import IoTNodeUI

# Mock Security Module se não existir
class MockSecurity:
    def verify_sink_signature(self, data, sig):
        return True # Aceita tudo por agora

class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, router):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.router = router
        
    def WriteValue(self, value, options):
        # value is bytes array
        try:
            val_bytes = bytes(value)
            
            # Tentar obter MAC do remetente
            device_path = options.get('device')
            mac = "unknown"
            if device_path:
                try:
                    # Parse final do path
                    # /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF
                    if 'dev_' in device_path:
                        mac_part = device_path.split('dev_')[1]
                        mac = mac_part.replace('_', ':')
                except:
                    pass
            
            print(f"[RX] Recebido {len(val_bytes)} bytes de {mac}")
            self.router.process_incoming_packet(val_bytes, mac)
            
        except Exception as e:
            print(f"[RX] Erro ao processar dados: {e}")

class NodeApplication(Application):
    def __init__(self, bus, router):
        super().__init__(bus)
        self.service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(self.service)
        self.char = RxCharacteristic(bus, 0, self.service, router)
        self.service.add_characteristic(self.char)

class Node:
    def __init__(self, nid_bytes):
        print(f"[*] A iniciar Nó com NID: {nid_bytes.hex()}")
        self.node_nid = nid_bytes
        
        # Inicializar componentes
        self.ble_manager = BLEManager(self.node_nid)
        self.security = MockSecurity()
        self.router = Router(self.node_nid, self.security, self.ble_manager)
        
        # Ligar BLEManager <-> Router
        # Router.set_uplink(conn, hops)
        # Router.handle_disconnection(conn)
        self.ble_manager.set_router_callbacks(self.router.set_uplink, self.router.handle_disconnection)
        
        # Configurar GATT Server
        self.app = NodeApplication(BUS, self.router)
        self.app.register()
        
        # Configurar Advertisement inicial
        self.ble_manager.start_advertising()
        
        self.running = True

    def start_logic_loop(self):
        t = threading.Thread(target=self._logic_loop)
        t.daemon = True
        t.start()

    def _logic_loop(self):
        time.sleep(2) # Esperar DBus estabilizar
        while self.running:
            # Monitorizar conexão
            self.ble_manager.monitor_connection_status()
            
            # Se não tiver uplink, procurar
            if not self.ble_manager.uplink_addr and self.ble_manager.hop_count == -1:
                self.ble_manager.find_and_connect_uplink()
            
            time.sleep(10)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/nodeA.crt", help="Caminho para o certificado do nó")
    args = parser.parse_args()

    # Ler NID do certificado
    nid_bytes = read_nid_from_cert(args.cert)
    if not nid_bytes:
        print("[!] Erro: Não foi possível obter NID do certificado.")
        sys.exit(1)

    # 1. Thread D-Bus/GLib
    loop = GLib.MainLoop()
    t_glib = threading.Thread(target=loop.run)
    t_glib.daemon = True
    t_glib.start()
    
    # 2. Inicializar Nó
    node = Node(nid_bytes)
    node.start_logic_loop()
    
    # 3. UI (Main Thread)
    root = tk.Tk()
    app = IoTNodeUI(root, node_ref=node)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        node.running = False
        loop.quit()

if __name__ == "__main__":
    main()
