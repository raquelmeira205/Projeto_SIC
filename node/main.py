import sys
import os
import threading
import time
import argparse
import tkinter as tk
from gi.repository import GLib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.bluez_classes import Application, Service, Characteristic
from common.ble_utils import BUS, SIC_SERVICE_UUID, SIC_RX_CHAR_UUID
from common.pki_utils import read_nid_from_cert
from node.ble_manager import BLEManager
from node.router import Router
from node.ui import IoTNodeUI


class MockSecurity:
    def verify_sink_signature(self, data, sig):
        return True


class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, router):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.router = router

    def WriteValue(self, value, options):
        data = bytes(value)
        mac = "unknown"

        device_path = options.get("device")
        if device_path and "dev_" in device_path:
            mac = device_path.split("dev_")[1].replace("_", ":")

        print(f"[RX] {len(data)} bytes de {mac}")
        self.router.process_incoming_packet(data, mac)


class NodeApplication(Application):
    def __init__(self, bus, router):
        super().__init__(bus)
        service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(service)

        char = RxCharacteristic(bus, 0, service, router)
        service.add_characteristic(char)


class Node:
    def __init__(self, nid):
        print(f"[*] Node iniciado: {nid.hex()}")

        # Guardar o NID também no Node para a UI
        self.node_nid = nid  

        self.ble_manager = BLEManager(nid)
        self.security = MockSecurity()
        self.router = Router(nid, self.security, self.ble_manager)

        self.ble_manager.set_router_callbacks(
            self.router.set_uplink,
            self.router.handle_disconnection
        )

        self.app = NodeApplication(BUS, self.router)
        self.app.register()

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

            if not self.ble_manager.uplink_addr and self.ble_manager.hop_count == -1:
                self.ble_manager.find_and_connect_uplink()

            time.sleep(10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/nodeA.crt")
    args = parser.parse_args()

    nid = read_nid_from_cert(args.cert)
    if not nid:
        sys.exit(1)

    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True).start()

    node = Node(nid)
    node.start_logic_loop()

    root = tk.Tk()
    ui = IoTNodeUI(root, node_ref=node)

    try:
        root.mainloop()
    finally:
        node.running = False
        loop.quit()


if __name__ == "__main__":
    main()
