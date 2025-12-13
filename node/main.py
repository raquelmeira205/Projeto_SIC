import sys
import time
import os
import threading
import tkinter as tk

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/..')

from common.security_wrapper import SecurityWrapper
from node.ble_manager import BLEManager
from node.router import Router
from node.ui import IoTNodeUI

# NOTE: Using NodeA for default. In production, pass arg.
NODE_NAME = "NodeA"
CERT_PATH = f"certs/{NODE_NAME}.crt"
KEY_PATH = f"certs/{NODE_NAME}.key"
CA_PATH = "certs/ca.crt"
SINK_CERT_PATH = "certs/sink.crt"

# NID: In reality, extract from Cert or config.
# Using a dummy 16-byte NID based on name for now.
# NodeA -> ...A
NODE_NID = b'\xAA' * 16

def main():
    print(f"=== STARTING IOT NODE ({NODE_NAME}) ===")
    
    # 0. Initialize DBus MainLoop (MUST be first)
    import dbus.mainloop.glib
    from gi.repository import GLib
    
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    
    # 1. Initialize Security
    if not os.path.exists(CERT_PATH):

        print(f"[!] Certificado {CERT_PATH} não encontrado. Gere os certificados primeiro.")
        return

    security = SecurityWrapper(CERT_PATH, KEY_PATH, CA_PATH, SINK_CERT_PATH)
    print("[OK] Security Module initialized.")

    # 2. Initialize Components (Cyclic dependency resolution)
    # Router needs BLEManager.
    # BLEManager needs a packet handler (Router.process_incoming_packet).
    
    # We instantiate BLEManager first with a placeholder or method reference
    ble_manager = BLEManager(NODE_NID) # Handler set later
    
    # Instantiate Router
    router = Router(NODE_NID, security, ble_manager)
    
    # Link BLEManager handler to Router
    ble_manager.gatt_server.packet_handler = router.process_incoming_packet
    
    print("[OK] BLE and Router initialized.")

    # 3. Start DBus Loop (Background)
    # Node functions as both Server (Advertiser) and Client (Scanner).
    # Client (simplepyble) is threaded.
    # Server (BlueZ) needs GLib MainLoop.
    # UI (Tkinter) needs its own MainLoop.
    
    # Conflict: Tkinter Loop vs GLib Loop.
    # Solution: Run GLib loop in a separate thread.
    
    # 3. Start DBus Loop (Background)
    # Node functions as both Server (Advertiser) and Client (Scanner).
    # Client (simplepyble) is threaded.
    # Server (BlueZ) needs GLib MainLoop.
    
    glib_loop = GLib.MainLoop()
    
    def run_glib():
        print("[Thread] GLib Loop starting...")
        glib_loop.run()
        print("[Thread] GLib Loop stopped.")

    glib_thread = threading.Thread(target=run_glib, daemon=True)
    glib_thread.start()

    # 4. Start BLE Server
    # Must be called after DBus setup
    ble_manager.gatt_server.start()
    
    # 5. Start UI (Main Thread)
    print("[UI] Starting Interface...")
    root = tk.Tk()
    app = IoTNodeUI(root, NODE_NID.hex(), ble_manager, router)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down...")
        # glib_loop.quit()

if __name__ == "__main__":
    main()
