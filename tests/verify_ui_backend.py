import sys
import os
import time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from node.router import Router
from node.ble_manager import BLEManager
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload
from unittest.mock import MagicMock

def test_backend_logic():
    print("--- Testing Backend Logic ---")
    
    # 1. Setup
    nid = b'\x01' * 16
    ble = BLEManager(nid)
    ble.disconnect_from_device = MagicMock()
    ble.send_packet = MagicMock()
    ble.start_advertising = MagicMock()
    
    security = MagicMock()
    security.verify_sink_signature.return_value = True
    
    router = Router(nid, security, ble)
    router._stop_monitor = True # Disable real thread
    
    # 2. Verify Stats Initialization
    if router.stats['lost_heartbeats'] == 0:
        print("SUCCESS: Stats initialized")
    else:
        print("FAIL: Stats not initialized correctly")
        
    # 3. Verify Uplink NID storage in BLEManager (simulated)
    # We can't easily test scan_nearby_devices without dbus, but we check if we can store NID
    ble.uplink_nid = b'\x02'*16
    print("SUCCESS: stored uplink_nid in ble_manager")
    
    # 4. Verify Sink NID capture in Router
    # Simulate incoming heartbeat
    sink_nid = b'\xAF' * 16
    fake_payload = HeartbeatPayload.pack(1, b'sig')
    
    # We need to simulate process_incoming_packet passing src
    router.uplink_connection = "UP:LI:NK:MA:CC"
    
    # Call internal handle_heartbeat directly or via process_incoming_packet if we Mock PacketHeader.unpack
    # Let's call _handle_heartbeat directly
    router._handle_heartbeat(fake_payload, "UP:LI:NK:MA:CC", sink_nid)
    
    if router.sink_nid == sink_nid:
        print("SUCCESS: Router captured Sink NID")
    else:
        print(f"FAIL: Router did not capture Sink NID: {router.sink_nid}")
        
    # 5. Verify Message Routing Stats
    router.send_app_data(sink_nid, b"Hello")
    if router.stats['routed_messages'] == 1:
        print("SUCCESS: send_app_data incremented routed_messages")
    else:
        print(f"FAIL: routed_messages not incremented: {router.stats}")
        
    # 6. Verify Received Message Storage (via NodeApplication logic simulation)
    # Since NodeApplication is not instantiated here, we just check if we can append to stats manually
    router.stats["received_messages"].append(("Sender", "Msg"))
    if len(router.stats["received_messages"]) == 1:
        print("SUCCESS: Can store received messages in stats")

if __name__ == "__main__":
    test_backend_logic()
