
#!/usr/bin/env python3
import sys
import os
import time
import argparse
import signal
# Add parent dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.bluez_classes import Advertisement, Application, Service, Characteristic
from common.ble_utils import BUS, SIC_SERVICE_UUID, ADAPTER_PATH

from sink.sink_identity import SinkIdentity
from sink.sink_ui_log import setup_logging, SinkUI
from sink.downlink_multicast import DownlinkMulticaster
from sink.heartbeat_broadcaster import HeartbeatBroadcaster

# --- Global object for signal handling ---
hb_broadcaster = None

def signal_handler(sig, frame):
    print("\n[Sink] Exiting...")
    if hb_broadcaster:
        hb_broadcaster.stop()
    sys.exit(0)

def main():
    global hb_broadcaster
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/sink.crt", help="Path to sink certificate")
    parser.add_argument("--key", default="certs/sink.key", help="Path to sink private key")
    args = parser.parse_args()

    setup_logging()
    ui = SinkUI()

    # 1. Load Myers Identity
    identity = SinkIdentity(args.cert, args.key)
    if not identity.load():
        ui.error("Failed to load identity")
        sys.exit(1)

    # 2. Setup Multicaster (Client)
    multicaster = DownlinkMulticaster()

    # 3. Setup Heartbeat Broadcaster
    hb_broadcaster = HeartbeatBroadcaster(identity, multicaster)


    # 4. Sink does NOT advertise (User Request). 
    # It acts as a Central, connecting to Nodes.
    
    # Start Heartbeats

    hb_broadcaster.start()

    # NOTE: How do we know about connected nodes? 
    # Nodes connect to Sink. Sink needs to list connected devices.
    # BlueZ keeps track of connected devices.
    # We can poll BlueZ or listen to PropertiesChanged.
    # For now, let's add a periodic check to populate multicaster.known_nodes_macs
    # Or rely on "downlink_multicast" logic to scan?
    # DownlinkMulticaster assumes we pass MACs.
    
    try:
        while True:
            # Simple discovery of connected peers via BlueZ to update Broadcaster list?
            # Or assume Multicaster handles it?
            # The user requested "heartbeat_broadcaster" to do "multi-unicast".
            # It needs targets.
            # I'll implement a simple poller here to update targets from BlueZ connected devices.
            
            # This logic mimics `sink/main.py`: `send_to_all_links`.
            # We get connected devices from BlueZ and register them in broadcaster.
            try:
                obj_manager = BUS.get("org.bluez", "/")
                objects = obj_manager.GetManagedObjects()
                for path, interfaces in objects.items():
                    if "org.bluez.Device1" in interfaces:
                        props = interfaces["org.bluez.Device1"]
                        if props.get("Connected", False):
                            mac = props.get("Address")
                            # Filter by UUID service?
                            if SIC_SERVICE_UUID.lower() in [u.lower() for u in props.get("UUIDs", [])]:
                                if mac not in hb_broadcaster.known_nodes_macs:
                                    ui.log(f"New node detected: {mac}")
                                    hb_broadcaster.register_node(mac)
            except Exception as e:
                pass
                
            time.sleep(5)
            
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
