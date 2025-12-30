# node/simplepy_client.py

import time
import simplepyble

# You already import these UUIDs elsewhere via common.ble_utils
from common.ble_utils import SIC_SERVICE_UUID, SIC_RX_CHAR_UUID


class SimplePyBleClient:
    """
    SimplePyBLE-based client used for uplink connections.

    - Server side (this node being connected TO) still uses BlueZ GATT.
    - Client side (this node connecting TO an uplink) uses SimplePyBLE.

    Connection handle = MAC string (same as Router/BLEManager use today).
    """

    def __init__(self, adapter_name: str = "hci0"):
        self.adapter_name = adapter_name
        self.adapter = None
        self.peripherals_by_mac = {}

        adapters = simplepyble.Adapter.get_adapters()
        if not adapters:
            raise RuntimeError("No BLE adapters found for SimplePyBLE")

        # Use first adapter by default (you can add matching by name if needed)
        self.adapter = adapters[0]
        print(f"[SimplePyBleClient] Using adapter: "
              f"{self.adapter.identifier()} [{self.adapter.address()}]")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_scan_peripheral(self, mac: str):
        """Return a simplepyble Peripheral for the given MAC, scanning if needed."""
        # Already cached and still valid
        if mac in self.peripherals_by_mac:
            return self.peripherals_by_mac[mac]

        print(f"[SimplePyBleClient] Scanning to find peripheral {mac}...")
        # Short scan just to populate the list
        self.adapter.scan_for(5000)
        peripherals = self.adapter.scan_get_results()
        for p in peripherals:
            if p.address() == mac:
                print(f"[SimplePyBleClient] Found {mac} as {p.identifier()}")
                self.peripherals_by_mac[mac] = p
                return p

        print(f"[SimplePyBleClient] Peripheral with MAC {mac} not found.")
        return None

    def _find_sic_characteristic(self, peripheral):
        """
        Find the service/characteristic pair for SIC GATT:

        - Service UUID: SIC_SERVICE_UUID
        - RX Characteristic UUID: SIC_RX_CHAR_UUID
        """
        services = peripheral.services()
        for svc in services:
            if svc.uuid().lower() == SIC_SERVICE_UUID.lower():
                for ch in svc.characteristics():
                    if ch.uuid().lower() == SIC_RX_CHAR_UUID.lower():
                        return svc.uuid(), ch.uuid()
        return None, None

    # ------------------------------------------------------------------
    # Public API used by BLEManager
    # ------------------------------------------------------------------

    def connect(self, mac: str) -> bool:
        """
        Connect to peripheral with given MAC using SimplePyBLE.

        Returns True on success.
        """
        peripheral = self._get_or_scan_peripheral(mac)
        if not peripheral:
            return False

        # Already connected?
        try:
            if peripheral.is_connected():
                print(f"[SimplePyBleClient] Already connected to {mac}")
                return True
        except Exception:
            # Not all backends expose is_connected()
            pass

        print(f"[SimplePyBleClient] Connecting to {mac}...")
        try:
            peripheral.connect()
        except Exception as e:
            print(f"[SimplePyBleClient] Connect failed for {mac}: {e}")
            return False

        print(f"[SimplePyBleClient] Connected to {mac}")
        # Optional: small delay for services to be ready
        time.sleep(0.5)
        return True

    def disconnect(self, mac: str) -> bool:
        """Disconnect from peripheral with given MAC, if known."""
        peripheral = self.peripherals_by_mac.get(mac)
        if not peripheral:
            return False
        try:
            peripheral.disconnect()
            print(f"[SimplePyBleClient] Disconnected from {mac}")
            return True
        except Exception as e:
            print(f"[SimplePyBleClient] Disconnect error for {mac}: {e}")
            return False

    def write_packet(self, mac: str, packet: bytes) -> bool:
        """
        Write a raw SIC packet to the RX characteristic on the remote node.

        This replaces BLEManager.send_packet's D-Bus write.
        """
        peripheral = self._get_or_scan_peripheral(mac)
        if not peripheral:
            return False

        # Ensure connected
        try:
            if not peripheral.is_connected():
                if not self.connect(mac):
                    return False
        except Exception:
            # If is_connected() not available, just try connect()
            if not self.connect(mac):
                return False

        svc_uuid, char_uuid = self._find_sic_characteristic(peripheral)
        if not svc_uuid or not char_uuid:
            print(f"[SimplePyBleClient] SIC characteristic not found on {mac}")
            return False

        try:
            # write_request = reliable write (like GATT Write With Response)
            peripheral.write_request(svc_uuid, char_uuid, packet)
            return True
        except Exception as e:
            print(f"[SimplePyBleClient] Write error to {mac}: {e}")
            return False
