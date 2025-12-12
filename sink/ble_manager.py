from sink.gatt_server import SinkGATTServer

class SinkBLEManager:
    def __init__(self, sink_nid, packet_handler_cb=None):
        self.sink_nid = sink_nid
        # sink is logic root, doesn't have uplink.
        # it has downlinks (connected nodes).
        
        self.gatt_server = SinkGATTServer(packet_handler_cb)
        
    def start(self):
        print("[SinkManager] Starting GATT Server...")
        self.gatt_server.start()
        
    def send_to_all_links(self, packet_bytes):
        """
        Broadcasts packet to all connected nodes via Notifications.
        """
        # In BLE Topology here, Sink -> Nodes is Downstream.
        # Use Notifications.
        # print(f"[SinkManager] Broadcasting {len(packet_bytes)} bytes...")
        self.gatt_server.send_notification(packet_bytes)
        return 1 # return success count dummy
