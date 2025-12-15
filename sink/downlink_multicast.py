
import time
import logging
import simplepyble
from common.constants import SIC_SERVICE_UUID, SIC_RX_CHAR_UUID

class DownlinkMulticaster:
    def __init__(self, adapter_name='hci0'):
        self.adapter = None
        self._init_adapter(adapter_name)
        self.connected_nodes = {} # map MAC -> Peripheral

    def _init_adapter(self, adapter_name):
        adapters = simplepyble.Adapter.get_adapters()
        if not adapters:
            logging.error("No Bluetooth adapters found")
            return

        # Attempt to find specific adapter or default to first
        for a in adapters:
            if adapter_name in a.identifier():
                self.adapter = a
                break
        
        if not self.adapter:
            self.adapter = adapters[0]
        
        logging.info(f"DownlinkMulticaster using adapter: {self.adapter.identifier()}[{self.adapter.address()}]")

    def connect_to_node(self, mac_address):
        if mac_address in self.connected_nodes:
            if self.connected_nodes[mac_address].is_connected():
                return True
        
        logging.info(f"Connecting to Node {mac_address}...")
        # Scan for specific device? Or assume we can connect by address directly?
        # simplepyble generally requires scanning to find the peripheral object first.
        # But for optimization, maybe we keep track of peripherals.
        
        # Quick scan to find the device
        self.adapter.scan_for(2000) # 2 seconds
        peripherals = self.adapter.scan_get_results()
        target = None
        for p in peripherals:
            if p.address() == mac_address:
                target = p
                break
        
        if target:
            try:
                target.connect()
                self.connected_nodes[mac_address] = target
                logging.info(f"Connected to {mac_address}")
                return True
            except Exception as e:
                logging.error(f"Failed to connect to {mac_address}: {e}")
                return False
        else:
            logging.warning(f"Node {mac_address} not found during scan.")
            return False

    def send_packet(self, mac_address, packet_bytes):
        if not self.adapter:
            return False

        if not self.connect_to_node(mac_address):
            return False
            
        p = self.connected_nodes[mac_address]
        try:
            # Write to the RX characteristic of the Node
            # We assume Node exposes SIC Service and Rx Char
            # We might need to discover services first? connected peripheral usually needs `discover_subscribers` or services
            # simplepyble: peripheral.services()
            
            # SimplePyBLE usually auto-discovers on connect?
            p.write_request(SIC_SERVICE_UUID, SIC_RX_CHAR_UUID, packet_bytes)
            logging.info(f"Sent {len(packet_bytes)} bytes to {mac_address}")
            return True
        except Exception as e:
            logging.error(f"Failed to write to {mac_address}: {e}")
            # Invalidate connection
            if mac_address in self.connected_nodes:
                 del self.connected_nodes[mac_address]
            return False

    def multicast(self, node_macs, packet_bytes):
        """
        Sends packet to all MACs in the list (Multi-Unicast)
        """
        success_count = 0
        for mac in node_macs:
             if self.send_packet(mac, packet_bytes):
                 success_count += 1
        return success_count
