
import logging
import simplepyble
import time

class BLEDiscovery:
    def __init__(self, adapter_name='hci0'):
        self.adapter = None
        self._init_adapter(adapter_name)

    def _init_adapter(self, adapter_name):
        adapters = simplepyble.Adapter.get_adapters()
        if not adapters:
            logging.error("No Bluetooth adapters found")
            return

        for a in adapters:
            if adapter_name in a.identifier():
                self.adapter = a
                break
        
        if not self.adapter:
            self.adapter = adapters[0] # Fallback
            
        logging.info(f"BLEDiscovery using adapter: {self.adapter.identifier()} [{self.adapter.address()}]")

    def scan(self, duration_ms=5000):
        if not self.adapter:
            return []
            
        logging.info(f"Scanning for {duration_ms}ms...")
        self.adapter.scan_for(duration_ms)
        results = self.adapter.scan_get_results()
        
        devices = []
        for p in results:
            # Extract Manufacturer Data to parse NID/Hop Count
            manuf_data = p.manufacturer_data()
            parsed_info = self._parse_manufacturer_data(manuf_data)
            
            # Basic info
            devices.append({
                'mac': p.address(),
                'name': p.identifier(),
                'rssi': p.rssi(),
                'connectable': p.is_connectable(),
                'peripheral': p, # Keep reference to simplepyble object
                'hop_count': parsed_info.get('hop_count', -1),
                'nid': parsed_info.get('nid', None)
            })
            
        return devices

    def _parse_manufacturer_data(self, manuf_data):
        # manuf_data is a dict usually: {int_id: bytes}
        # We look for 0xFFFE
        info = {'hop_count': -1, 'nid': None}
        
        CUSTOM_ADV_ID = 0xFFFE
        if CUSTOM_ADV_ID in manuf_data:
            data = manuf_data[CUSTOM_ADV_ID]
            if len(data) >= 1:
                info['hop_count'] = data[0]
                if len(data) > 1:
                    info['nid'] = data[1:]
        return info
