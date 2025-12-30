from gi.repository import GLib

from common.ble_utils import (
    BUS,
    ADAPTER_PATH,
    scan_nearby_devices,
    get_device_object,
    SIC_RX_CHAR_UUID,
)
from common.bluez_classes import Advertisement

import simplepy_client  # node/simplepy_client.py


class BLEManager:
    def __init__(self, node_nid: bytes):
        self.node_nid = node_nid

        self.uplink_addr = None
        self.uplink_nid = None
        self.downlinks = {}
        self.forwarding_table = {}

        self.hop_count = -1
        self.advertisement = None

        self.router_callback_connect = None
        self.router_callback_disconnect = None

        # índice único DBus (evita colisões)
        self.adv_index = node_nid[-1]

        # SimplePyBLE-based client (uplink side)
        self.client = simplepy_client.SimplePyBleClient("hci0")

    # ------------------------------------------------------------------
    # Callbacks Router
    # ------------------------------------------------------------------

    def set_router_callbacks(self, on_connect, on_disconnect):
        self.router_callback_connect = on_connect
        self.router_callback_disconnect = on_disconnect

    # ------------------------------------------------------------------
    # Advertisement (server side, BlueZ)
    # ------------------------------------------------------------------

    def start_advertising(self):
        if self.advertisement:
            return

        print(f"[*] Advertising (Hop Count={self.hop_count})")

        self.advertisement = Advertisement(
            BUS,
            index=self.adv_index,
            advertising_type="peripheral",
        )

        # Hop count: -1 → 0xFF
        hc = self.hop_count if self.hop_count >= 0 else 0xFF
        payload = bytes([hc]) + self.node_nid

        print(
            f"[DEBUG] Node advertising: ID=0xFFFE ({0xFFFE}), "
            f"hop={hc}, payload={payload.hex()}"
        )
        self.advertisement.add_manufacturer_data(0xFFFE, payload)

        try:
            self.advertisement.register(ADAPTER_PATH)
        except Exception as e:
            print(f"[!] Advertisement falhou: {e}")
            self.advertisement = None

    def update_advertisement(self):
        if self.advertisement:
            try:
                self.advertisement.unregister(ADAPTER_PATH)
            except Exception:
                pass
            self.advertisement = None

        self.start_advertising()

    # ------------------------------------------------------------------
    # GATT Send (client side, SimplePyBLE)
    # ------------------------------------------------------------------

    def send_packet(self, dest_mac, packet):
        # Router calls this for any outgoing packet over BLE
        return self.client.write_packet(dest_mac, packet)

    # ------------------------------------------------------------------
    # Conexões (uplink client side)
    # ------------------------------------------------------------------

    def connect_to_device(self, mac):
        # Used by CLI force_connect and by find_and_connect_uplink
        return self.client.connect(mac)

    def disconnect_from_device(self, mac):
        ok = self.client.disconnect(mac)

        if ok and mac == self.uplink_addr:
            self.trigger_chain_disconnection()
            if self.router_callback_disconnect:
                self.router_callback_disconnect(mac)

        return ok

    # ------------------------------------------------------------------
    # Uplink logic
    # ------------------------------------------------------------------

    def scan_for_devices(self):
        """Manual scan for nearby devices using SimplePyBLE."""
        print("\n--- Manual scan for devices (using simplepyble) ---")

        try:
            from node.ble_discovery import BLEDiscovery
            import time

            scanner = BLEDiscovery("hci0")
            devices = scanner.scan(duration_ms=10000)  # 10 second scan

            # Convert to expected format
            result = []
            for dev in devices:
                hop = dev.get("hop_count", -1)
                if hop >= 0:  # Only include valid SIC devices
                    result.append(
                        {
                            "mac": dev["mac"],
                            "name": dev.get("name", "Unknown"),
                            "hop_count": hop,
                            "rssi": dev.get("rssi", 0),
                            "nid": dev.get("nid"),
                        }
                    )
                    print(
                        f"  Found: {dev['mac']} | Hop:{hop} | "
                        f"RSSI:{dev.get('rssi', 0)}"
                    )

            # Optional: short BlueZ discovery just to register devices in D-Bus
            if result:
                print("[*] Registering devices in BlueZ D-Bus...")
                try:
                    adapter = BUS.get("org.bluez", ADAPTER_PATH)
                    adapter.StartDiscovery()
                    time.sleep(2)
                    adapter.StopDiscovery()
                except Exception as e:
                    print(f"[!] D-Bus registration warning: {e}")

            print(f"[*] Found {len(result)} SIC devices")
            return result

        except Exception as e:
            print(f"[!] SimplePyBLE scan error: {e}")
            print("[!] Falling back to D-Bus scan...")

            devices = scan_nearby_devices(duration=10)
            result = []
            for mac, name, hop, rssi, nid in devices:
                if hop >= 0:
                    result.append(
                        {
                            "mac": mac,
                            "name": name,
                            "hop_count": hop,
                            "rssi": rssi,
                            "nid": nid,
                        }
                    )

            print(f"[*] Found {len(result)} devices")
            return result

    def find_and_connect_uplink(self):
        print("\n--- Procurando uplink ---")

        # Use the same data as CLI scan (SimplePyBLE)
        devices = self.scan_for_devices()
        if not devices:
            print("[!] Nenhum uplink encontrado")
            return False

        # menor hop, melhor RSSI
        candidates = [d for d in devices if d["hop_count"] >= 0]
        if not candidates:
            print("[!] Nenhum uplink encontrado (sem hop válido)")
            return False

        best = min(
            candidates,
            key=lambda d: (d["hop_count"], -d["rssi"]),
        )

        mac = best["mac"]
        name = best["name"]
        hop = best["hop_count"]
        rssi = best["rssi"]
        nid = best["nid"]

        print(f"[*] Uplink escolhido: {name} {mac} (hop={hop}, rssi={rssi})")

        if self.connect_to_device(mac):
            self.uplink_addr = mac
            self.uplink_nid = nid  # Store NID
            self.hop_count = hop + 1
            self.update_advertisement()

            if self.router_callback_connect:
                self.router_callback_connect(mac, hop)

            return True

        return False

    # ------------------------------------------------------------------
    # Chain disconnection (server + router side)
    # ------------------------------------------------------------------

    def trigger_chain_disconnection(self):
        print("[!!!] Perda de uplink (Nível BLE)")

        self.uplink_addr = None
        self.uplink_nid = None
        self.hop_count = -1

        self.update_advertisement()

    def monitor_connection_status(self):
        if not self.uplink_addr:
            return

        try:
            device = get_device_object(self.uplink_addr)
            if not device or not device.Connected:
                self.trigger_chain_disconnection()
        except Exception:
            # Se der erro a aceder ao objeto, assumimos que desconectou
            self.trigger_chain_disconnection()
