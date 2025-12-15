
# Adapted from gatt_server.py
from pydbus import SystemBus
from gi.repository import GLib
import sys
import logging
from common.bluez_classes import Application, Service, Characteristic
from common.constants import SIC_SERVICE_UUID, SIC_RX_CHAR_UUID, NID_SIZE

class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, callback):
        # We pass ['write'] flags
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write'], service)
        self.callback = callback

    def WriteValue(self, value, options):
        # Value is bytes
        data = bytes(value)
        
        # Determine Sender MAC if possible from options
        sender = "unknown"
        if "device" in options:
             dev_path = options["device"]
             # /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX
             parts = dev_path.split('_')
             if len(parts) >= 6:
                 sender = ":".join(parts[-6:])

        if self.callback:
            self.callback(data, sender)

class NodeGATTServer:
    def __init__(self, bus, recv_callback):
        self.bus = bus
        self.app = Application(bus)
        self.service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.app.add_service(self.service)
        
        self.char = RxCharacteristic(bus, 0, self.service, recv_callback)
        self.service.add_characteristic(self.char)
        
        self.registered = False

    def start(self):
        if not self.registered:
            try:
                self.app.register()
                self.registered = True
                logging.info("Node GATT Server Started")
            except Exception as e:
                logging.error(f"Failed to start GATT Server: {e}")
