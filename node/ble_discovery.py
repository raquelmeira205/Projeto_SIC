"""
BLE Discovery using SimplePyBLE

Provides a wrapper around simplepyble for scanning BLE devices
"""

import simplepyble


class BLEDiscovery:
    """Wrapper for SimplePyBLE to scan for BLE devices"""

    def __init__(self, adapter_name='hci0'):
        """
        Initialize BLE scanner

        Args:
            adapter_name: Name of the BLE adapter (e.g., 'hci0')
        """
        self.adapter_name = adapter_name
        self.adapter = None

        # Get available adapters
        adapters = simplepyble.Adapter.get_adapters()
        if not adapters:
            raise RuntimeError("No BLE adapters found")

        # Use the first adapter by default
        # TODO: Could match by adapter_name if needed
        self.adapter = adapters[0]
        print(f"[BLEDiscovery] Using adapter: {self.adapter.identifier()} [{self.adapter.address()}]")

    def scan(self, duration_ms=10000):
        """
        Scan for BLE devices

        Args:
            duration_ms: Scan duration in milliseconds

        Returns:
            List of discovered devices with their information
        """
        if not self.adapter:
            raise RuntimeError("Adapter not initialized")

        print(f"[BLEDiscovery] Scanning for {duration_ms}ms...")

        # Start scanning
        self.adapter.scan_for(duration_ms)

        # Get scan results
        peripherals = self.adapter.scan_get_results()
        print(f"[BLEDiscovery] Found {len(peripherals)} devices")

        devices = []

        for peripheral in peripherals:
            device_info = {
                'mac': peripheral.address(),
                'name': peripheral.identifier(),
                'rssi': peripheral.rssi() if hasattr(peripheral, 'rssi') else 0,
                'hop_count': -1,  # Will be extracted from manufacturer data
                'nid': None,
                'peripheral': peripheral,  # <-- importante para o cache
            }

            # Parse manufacturer data to extract SIC protocol info
            manufacturer_data = peripheral.manufacturer_data()
            for company_id, data in manufacturer_data.items():
                # Check if this is our custom advertisement (0xFFFE)
                if company_id == 0xFFFE and len(data) >= 17:
                    # Data format: [hop_count (1 byte)] + [NID (16 bytes)]
                    device_info['hop_count'] = data[0]
                    device_info['nid'] = bytes(data[1:17])
                    break

            devices.append(device_info)

        return devices
