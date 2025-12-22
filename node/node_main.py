
#!/usr/bin/env python3
import sys
import os
import time
import threading
import argparse
import logging
from gi.repository import GLib

# Add parent dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.certificate_parser import read_nid_from_cert
from common.packet_headers import PacketHeader, MsgType, HeartbeatPayload
from common.constants import SIC_SERVICE_UUID
from common.bluez_classes import Advertisement
from common.ble_utils import BUS, ADAPTER_PATH  # We still need BUS for Advertisement

from node.ble_discovery import BLEDiscovery
from node.uplink_selector import UplinkSelector
from node.heartbeat_timeout import HeartbeatMonitor
from node.node_gatt_server import NodeGATTServer
from node.node_ui import NodeUI

class Node:
    def __init__(self, cert_path, key_path):
        self.cert_path = cert_path
        self.key_path = key_path
        
        # Load ID
        try:
             self.nid = read_nid_from_cert(cert_path)
             if not self.nid: raise ValueError("Empty NID")
        except Exception as e:
             print(f"Failed to load cert: {e}")
             sys.exit(1)

        # State
        self.sink_nid = None
        self.current_uplink_mac = None
        self.hop_count = 0 # Testing: Force Hop Count 0
        self.forwarding_table = {} # Dest NID bytes -> Next Hop MAC
        self.stats = {'lost_heartbeats': 0, 'routed_messages': 0}
        self.scan_results = []

        # Components
        self.ble_discovery = BLEDiscovery()
        self.uplink_selector = UplinkSelector(self.ble_discovery)
        self.hb_monitor = HeartbeatMonitor(self._on_heartbeat_timeout)
        self.gatt_server = NodeGATTServer(BUS, self._on_packet_received)
        self.ui = NodeUI(self)
        
        self.advertisement = None
        self.running = False

    def start(self):
        self.running = True
        
        # 1. Start GLib Loop in Thread (Must be first to handle DBus callbacks)
        self.t_glib = threading.Thread(target=self._run_glib, daemon=True)
        self.t_glib.start()
        
        # 2. Start GATT Server (Registers with BlueZ, requires Loop)
        self.gatt_server.start()
        
        # 2. Start Logic Loop (Uplink, etc)
        self.t_logic = threading.Thread(target=self._logic_loop, daemon=True)
        self.t_logic.start()
        
        # 3. Start Advertisement
        self._update_advertisement()

        # 4. Start UI (Blocking)
        try:
            self.ui.start()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        if self.advertisement:
            try:
                self.advertisement.unregister(ADAPTER_PATH)
            except:
                pass
        print("\nNode stopped. Returning to terminal.")

    def reset_stats(self):
        self.stats = {'lost_heartbeats': 0, 'routed_messages': 0}

    def _run_glib(self):
        loop = GLib.MainLoop()
        loop.run()

    def _logic_loop(self):
        while self.running:
            # Check Uplink
            if not self.current_uplink_mac:
                self.ui.log("Scanning for Uplink...")
                best, candidates = self.uplink_selector.select_best_uplink()
                if candidates:
                    self.scan_results = candidates
                    self.ui.update_scan_results(candidates)
                if best:
                    self._connect_uplink(best)
            
            # Monitoring
            self.hb_monitor.check()
            
            time.sleep(5)

    def _connect_uplink(self, uplink_info):
        # Uplink info has 'peripheral', 'hop_count', 'nid'
        mac = uplink_info['mac']
        hop = uplink_info['hop_count']
        nid = uplink_info['nid']
        
        self.ui.log(f"Connecting Uplink: {mac} (Hop {hop})")
        
        # Do we need to maintain an open connection object?
        # Yes if we want to send data up efficiently.
        # But simplepyble might disconnect if we don't hold the reference.
        # uplifting_info['peripheral'] is the object.
        
        try:
            p = uplink_info['peripheral']
            if not p.is_connected():
                p.connect()
            
            self.current_uplink_mac = mac
            self.hop_count = hop + 1
            # Update Advertisement to reflect new Hop Count
            self._update_advertisement()
            
            self.hb_monitor.start()
            self.ui.log(f"Uplink Established. My Hop Count: {self.hop_count}")
            
        except Exception as e:
            self.ui.log(f"Failed to connect uplink {mac}: {e}")

    def _on_heartbeat_timeout(self):
        self.stats['lost_heartbeats'] += 1
        self.ui.log("Heartbeat Timeout! Lost Uplink.")
        # Disconnect uplink
        self.current_uplink_mac = None
        self.hop_count = -1
        self._update_advertisement()
        self.hb_monitor.stop()

    def _update_advertisement(self):
        # Register/Update Advertisement with BlueZ
        # We need a unique index ideally, or just 0
        if self.advertisement:
             try: self.advertisement.unregister(ADAPTER_PATH)
             except: pass
        
        self.advertisement = Advertisement(BUS, 0, 'peripheral')
        self.advertisement.add_local_name(f"SIC-Node-{self.nid.hex[-4:]}")
        self.advertisement.add_service_uuid(SIC_SERVICE_UUID)
        
        # Manuf Data: Hop Count + NID (or partial NID)
        hc = self.hop_count if self.hop_count >= 0 else 0xFF
        payload = bytes([hc]) + self.nid.bytes
        self.advertisement.add_manufacturer_data(0xFFFE, payload)
        
        try:
             self.advertisement.register(ADAPTER_PATH)
        except Exception as e:
             self.ui.log(f"Adv Reg Failed: {e}")

    def _on_packet_received(self, data, sender_mac):
        try:
            # Parse Packet
            src, dest, mtype, payload = PacketHeader.unpack(data)
            self.ui.log(f"Msg from {src.hex()[:4]}.. to {dest.hex()[:4]}.. Type={mtype}")
            
            # 1. Is it for me?
            if dest == self.nid.bytes:
                 self._handle_local_packet(src, mtype, payload)
                 return
            
            # 2. Is it Heartbeat? (Variables like Broadcast/Multicast)
            if mtype == MsgType.HEARTBEAT:
                self._handle_heartbeat(payload, src)
                
            # 3. Forwarding Logic
            # If for me or Broadcast -> Processed.
            # If unicast for others -> Route.
            if dest != self.nid.bytes:
                 self._route_packet(dest, data)
                 
        except Exception as e:
            self.ui.log(f"Packet Error: {e}")

    def _handle_heartbeat(self, payload, src_nid):
        # Check signature (Mocking or using common.crypto)
        # Verify it came from Uplink?
        # Update monitor
        self.hb_monitor.heartbeat_received()
        
        seq, sig = HeartbeatPayload.unpack(payload)
        self.ui.log(f"Heartbeat #{seq} received.")
        
        # Capture Sink NID if first time
        if not self.sink_nid and self.hop_count > 0:
             self.sink_nid = src_nid # Approx logic, usually source of HB is Sink
             
        # Forward Heartbeat Downstream?
        # We need to broadcast it to our downlinks.
        # But we are utilizing "Advertised" topology mostly.
        # If we have connected downlinks (Nodes that connected to US), we should write to them.
        # But NodeGATTServer doesn't track connected downlinks automatically unless we implement it.
        # We can implement a "Downlink Manager" similar to Sink's if needed.
        pass

    def _route_packet(self, dest_nid, raw_data):
        self.stats['routed_messages'] += 1
        # Look up next hop
        # If in forwarding table -> send
        # Else -> send to uplink? (Default Route)
        
        # Simulating routing:
        if self.current_uplink_mac:
            # Send UP to Uplink
             # We need to write to Uplink's RX Char
             # We have 'peripheral' object in _connect_uplink? We didn't store it globally.
             # Ideally we should store Uplink Peripheral object.
             pass

    def _handle_local_packet(self, src, mtype, payload):
        if mtype == MsgType.DATA:
             self.ui.log(f"Data received: {payload}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/nodeA.crt")
    parser.add_argument("--key", default="certs/nodeA.key")
    args = parser.parse_args()
    
    node = Node(args.cert, args.key)
    node.start()

if __name__ == "__main__":
    main()
