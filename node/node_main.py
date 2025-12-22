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
from common.packet_structs import PacketHeader, MsgType
from common.constants import SIC_SERVICE_UUID
from common.ble_utils import BUS, ADAPTER_PATH

from node.ble_manager import BLEManager
from node.router import Router
from node.node_gatt_server import NodeGATTServer
from node.node_ui import NodeUI
from common.security_handshake import SecurityHandshake
from node.ble_handshake_transport import BLEHandshakeTransport

class Node:
    def __init__(self, cert_path, key_path, ca_cert_path="certs/ca.crt"):
        self.cert_path = cert_path
        self.key_path = key_path
        
        # Load ID
        try:
             self.nid = read_nid_from_cert(cert_path)
             if not self.nid: raise ValueError("Empty NID")
        except Exception as e:
             print(f"Failed to load cert: {e}")
             sys.exit(1)

        # Components
        self.ble = BLEManager(self.nid.bytes)
        self.security = SecurityHandshake(cert_path, key_path, ca_cert_path)
        self.router = Router(self.nid.bytes, self.security, self.ble)
        self.gatt_server = NodeGATTServer(BUS, self._on_packet_received)
        self.ui = NodeUI(self)
        
        self.running = False
        self.handshake_transport = None

        # Expose properties for UI
        self.stats = self.router.stats
        self.forwarding_table = self.router.forwarding_table
        
    @property
    def current_uplink_mac(self):
        return self.ble.uplink_addr
        
    @property
    def hop_count(self):
        return self.ble.hop_count
        
    @property
    def sink_nid(self):
        return self.router.sink_nid

    def start(self):
        self.running = True
        
        # 1. Start GLib Loop
        self.t_glib = threading.Thread(target=self._run_glib, daemon=True)
        self.t_glib.start()
        
        # 2. Start GATT Server
        self.gatt_server.start()
        
        # 3. Start Advertisement
        self.ble.start_advertising()
        
        # 4. Start Logic Loop
        self.t_logic = threading.Thread(target=self._logic_loop, daemon=True)
        self.t_logic.start()

        # 5. Start UI
        try:
            self.ui.start()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        self.ble.update_advertisement() # Cleans up if logic handled
        print("\nNode stopped.")

    def reset_stats(self):
        self.router.stats['lost_heartbeats'] = 0
        self.router.stats['routed_messages'] = 0

    def _run_glib(self):
        loop = GLib.MainLoop()
        loop.run()

    def _logic_loop(self):
        while self.running:
            # Periodic Scan if not connected
            if not self.ble.uplink_addr:
                self.ui.log("Scanning...")
                raw_devices = self.ble.scan(duration=4)
                
                # Convert tuples to dicts for UI
                # Tuple: (mac, name, hop, rssi, nid)
                candidates = []
                for d in raw_devices:
                    # Show all devices, even if not part of network (Hop=-1)
                    candidates.append({
                        'mac': d[0],
                        'name': d[1],
                        'hop_count': d[2],
                        'rssi': d[3],
                        'nid': d[4]
                    })
                
                self.ui.update_scan_results(candidates)
            else:
                # Update advertisement if needed, verify connection
                self.ble.monitor_connection_status()
            
            time.sleep(2)

    def connect_manual(self, candidate):
        mac = candidate['mac']
        hop = candidate['hop_count']
        peer_nid = candidate['nid']
        
        self.ui.log(f"Connecting to {mac}...")
        
        # 1. Connect BLE
        if not self.ble.connect_to_device(mac):
            self.ui.log("BLE Connection Failed")
            return
            
        self.ui.log("BLE Connected. Starting Handshake...")
        
        # 2. Handshake
        try:
            self.handshake_transport = BLEHandshakeTransport(self.ble, mac, self.nid, peer_nid)
            self.security.perform_handshake(self.handshake_transport)
            session_key = self.security.session_key
            
            self.ui.log("Handshake Success!")
            
            # 3. Register with Router / BLE Manager
            self.ble.uplink_addr = mac
            self.ble.hop_count = hop + 1
            self.ble.update_advertisement()
            
            self.router.set_uplink(mac, hop, session_key)
            self.ui.log(f"Uplink set. Hop Count: {self.ble.hop_count}")
            
        except Exception as e:
            self.ui.log(f"Handshake Failed: {e}")
            self.ble.disconnect_from_device(mac)
            self.handshake_transport = None

    def _on_packet_received(self, data, sender_mac):
        try:
            # Peek at header to check type
            if len(data) < PacketHeader.SIZE:
                return

            src, dest, mtype, payload, seq, mac = PacketHeader.unpack(data)
            
            if mtype == MsgType.HANDSHAKE:
                 if self.handshake_transport:
                     # We assume handshake transport is active if we are expecting one?
                     # Or request from downlink?
                     # If we are the Acceptor (Downlink connecting to us), we need to handle that too?
                     # The USER request only mentioned "User chooses uplink".
                     # But we must support incoming handshakes if we are an uplink for someone else?
                     # "SecurityHandshake integration... Protocol Flow: Connection... _connect_uplink method is called."
                     # The user prompt focused on the Node behaving as a client connecting to Uplink.
                     # But if another Node connects to US, we are the Server/Uplink.
                     # The prompt says: "When a link is established (e.g., via Force Connect), the _connect_uplink method is called."
                     # It describes the ACTIVE connection side.
                     # For the passive side (serving), `SecurityHandshake` module might need to be called in `accept` mode?
                     # The `SecurityHandshake.perform_handshake` code (Step 18) initiates: `exchange_certificates`, `verify`, `generate_ephemeral_key`.
                     # It seems symmetric or client-driven?
                     # `exchange_certificates`: Send my cert, receive peer cert.
                     # `perform_handshake`: 
                     #   exchange_certificates
                     #   verify_peer_certificate
                     #   generate_ephemeral_key
                     #   sign_ephemeral_key
                     #   send(pub), send(sig)
                     #   receive(pub), receive(sig)
                     # This protocol is SYMMETRIC/Synchronous. Both sides must do it.
                     # If I receive a HANDSHAKE packet, it means someone is initiating handshake or responding?
                     # If I didn't initiate, I should probably handle it.
                     # But the Prompt "The node displays... user should choose... integrated... perform_handshake is executed."
                     # I will focus on the Client Side (Connecting to Uplink) as requested.
                     # Handling incoming handshakes might be implicit or out of scope for this specific task "nodes choose automatically... that needs to change".
                     
                     self.handshake_transport.on_packet_received(payload)
                 else:
                     # Maybe an incoming connection trying to handshake?
                     # For now ignore or log.
                     pass
            else:
                 self.router.process_incoming_packet(data, sender_mac)

        except Exception as e:
            print(f"Packet Error: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/nodeA.crt")
    parser.add_argument("--key", default="certs/nodeA.key")
    parser.add_argument("--ca", default="certs/ca.crt")
    args = parser.parse_args()
    
    node = Node(args.cert, args.key, args.ca)
    node.start()

if __name__ == "__main__":
    main()
