import sys
import time
import os
import threading

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/..')

from common.security_wrapper import SecurityWrapper
from sink.ble_manager import SinkBLEManager
from sink.heartbeat_service import HeartbeatService

# Configuration
SINK_NID = b'\x00' * 16 # Root NID (all zeros for instance)
CERT_PATH = "certs/sink.crt"
KEY_PATH = "certs/sink.key"
CA_PATH = "certs/ca.crt"

def main():
    print("=== STARTING SINK DEVICE ===")
    
    # 0. Initialize DBus MainLoop (MUST be first)
    # This prepares DBus to use GLib's main loop for async operations.
    import dbus.mainloop.glib
    from gi.repository import GLib

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    # 1. Initialize Security
    if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):

        print("[!] Erro: Certificados não encontrados em certs/")
        return

    security = SecurityWrapper(CERT_PATH, KEY_PATH, CA_PATH)
    print("[OK] Security Module initialized.")

    # 2. Initialize BLE Manager
    # Packet Handler: What does Sink do with received data?
    # For now, just print it.
    def packet_handler(data, src_mac):
        print(f"[SinkRx] Recebido de {src_mac}: {len(data)} bytes")
        # Could parse packet, check destination (Inbox), etc.

    ble_manager = SinkBLEManager(SINK_NID, packet_handler)
    
    # 3. Connection Manager Mock
    # HeartbeatService expects a 'conn_manager' with 'send_to_all_links' method.
    # SinkBLEManager has it.
    
    # 4. Initialize Heartbeat Service
    heartbeat = HeartbeatService(SINK_NID, ble_manager, security)
    
    # 5. Start Components
    try:
        # Start BLE (Advertisements & GATT)
        # Note: DBus loop usually needs to block or run in thread.
        # But our simple implementation instantiates objects. 
        # We need a Loop for DBus to work properly if receiveing.
        # simplepyble (Client) has its own loop/threads.
        # pydbus/BlueZ server needs a GLib MainLoop.
        
        # Start BLE (Advertisements & GATT)
        
        # Start Heartbeat (Threaded)
        heartbeat.start()
        
        # Start BLE Manager (GATT Server registration)
        try:
            ble_manager.start()
        except Exception as e:
            print(f"[!] Erro ao iniciar servidor GATT: {e}")
            print("[!] Verifique se o serviço Bluetooth está rodando: sudo systemctl start bluetooth")
            heartbeat.stop()
            return

        print("[*] Sink Running. Press Ctrl+C to stop.")
        loop.run()

    except KeyboardInterrupt:
        print("\nStopping...")
        heartbeat.stop()

if __name__ == "__main__":
    main()
