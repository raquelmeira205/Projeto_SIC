from gi.repository import GLib
from common.ble_utils import (
    BUS,
    ADAPTER_PATH,
    scan_nearby_devices,
    get_device_object,
    get_gatt_characteristic,
    SIC_RX_CHAR_UUID,
)
from common.bluez_classes import Advertisement


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
        
        # Multiple Sinks / Failover
        self.uplink_candidates = [] # List of tuples: (mac, name, hop, rssi, nid)
        self.current_candidate_index = 0

        # índice único DBus (evita colisões)
        self.adv_index = node_nid[-1]

    # ------------------------------------------------------------------
    # Callbacks Router
    # ------------------------------------------------------------------

    def set_router_callbacks(self, on_connect, on_disconnect):
        self.router_callback_connect = on_connect
        self.router_callback_disconnect = on_disconnect

    # ------------------------------------------------------------------
    # Advertisement
    # ------------------------------------------------------------------

    def start_advertising(self):
        if self.advertisement:
            return

        print(f"[*] Advertising (Hop Count={self.hop_count})")

        self.advertisement = Advertisement(
            BUS,
            index=self.adv_index,
            advertising_type="peripheral"
        )

        # Hop count: -1 → 0xFF
        hc = self.hop_count if self.hop_count >= 0 else 0xFF
        payload = bytes([hc]) + self.node_nid
        
        print(f"[DEBUG] Node advertising: ID=0xFFFE ({0xFFFE}), hop={hc}, payload={payload.hex()}")
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
    # GATT Send
    # ------------------------------------------------------------------

    def send_packet(self, dest_mac, packet):
        device = get_device_object(dest_mac)

        if not device or not device.Connected:
            if not self.connect_to_device(dest_mac):
                return False

        # Wait for services to be discovered
        try:
            if not device.ServicesResolved:
                # Only print if we are actually going to wait
                if not get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID):
                    print(f"[BLE] Waiting for service discovery on {dest_mac}...")
                    import time
                    for i in range(20):  # Wait up to 2 seconds
                        time.sleep(0.1)
                        if device.ServicesResolved or get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID):
                            # print(f"[BLE] Ready for {dest_mac}")
                            break
                    else:
                        print(f"[BLE] Warning: Services not resolved for {dest_mac}, attempting anyway...")
        except:
            pass  # Property might not exist

        char = get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID)
        if not char:
            return False

        try:
            char.WriteValue(packet, {})
            return True
        except Exception:
            return False

    def write_value(self, mac, data):
       
        return self.send_packet(mac, data)

    # ------------------------------------------------------------------
    # Conexões
    # ------------------------------------------------------------------

    def connect_to_device(self, mac):
        import time
        from gi.repository import GLib
        
        # Wait for device to appear in D-Bus (from scan)
        max_wait = 5
        device = None
        for i in range(max_wait):
            device = get_device_object(mac)
            if device:
                break
            print(f"[*] Aguardando dispositivo aparecer no D-Bus... ({i+1}/{max_wait})")
            time.sleep(1)
        
        if not device:
            print(f"[!] Dispositivo {mac} não encontrado no D-Bus")
            return False

        try:
            # Check if already connected
            if hasattr(device, 'Connected') and device.Connected:
                print(f"[*] Já conectado a {mac}")
                return True
            
            print(f"[*] Conectando a {mac} via BLE...")
            
            # Try to connect using the adapter's ConnectDevice method for LE
            connection_initiated = False
            try:
                # Access the correct D-Bus interface
                adapter = BUS.get("org.bluez", ADAPTER_PATH)['org.bluez.Adapter1']
                # Use ConnectDevice with address type for LE connections
                properties = {
                    'Address': GLib.Variant('s', mac),
                    'AddressType': GLib.Variant('s', 'public')  # Force LE public address
                }
                result = adapter.ConnectDevice(properties)
                print(f"[*] ConnectDevice retornou: {result}")
                connection_initiated = True
            except Exception as e:
                print(f"[!] ConnectDevice falhou: {e}")
                # Fallback to direct Connect
                try:
                    device.Connect()
                    connection_initiated = True
                except Exception as e2:
                    # Check if error is "already in progress" which means connection is happening
                    if 'InProgress' in str(e2) or 'busy' in str(e2).lower():
                        print(f"[*] Conexão já em progresso")
                        connection_initiated = True
                    else:
                        print(f"[!] Connect também falhou: {e2}")
            
            if not connection_initiated:
                return False
            
            # Wait for connection to establish
            print(f"[*] Aguardando conexão estabelecer...")
            for i in range(15):  # Increased timeout
                time.sleep(0.5)
                device = get_device_object(mac)  # Refresh device object
                if device and hasattr(device, 'Connected') and device.Connected:
                    print(f"[*] ✓ Conexão estabelecida com {mac}")
                    
                    # Re-advertise to remain discoverable for other nodes
                    # This is critical for multi-hop topology
                    print(f"[*] Re-advertising to remain discoverable...")
                    self.update_advertisement()
                    
                    return True
            
            print(f"[!] Timeout aguardando conexão, mas pode estar conectado")
            # Check one last time
            device = get_device_object(mac)
            if device and hasattr(device, 'Connected') and device.Connected:
                print(f"[*] ✓ Conexão confirmada!")
                
                # Re-advertise to remain discoverable for other nodes
                print(f"[*] Re-advertising to remain discoverable...")
                self.update_advertisement()
                
                return True
            
            return False
            
        except Exception as e:
            print(f"[!] Erro conexão {mac}: {e}")
            return False


    def disconnect_from_device(self, mac):
        device = get_device_object(mac)
        if not device:
            return False

        try:
            device.Disconnect()

            if mac == self.uplink_addr:
                self.trigger_chain_disconnection()

            if self.router_callback_disconnect:
                self.router_callback_disconnect(mac)

            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Uplink logic
    # ------------------------------------------------------------------

    def scan_for_devices(self):
        """Manual scan for nearby devices without connecting - using simplepyble"""
        print("\n--- Manual scan for devices (using simplepyble) ---")
        
        try:
            from node.ble_discovery import BLEDiscovery
            import time
            
            scanner = BLEDiscovery('hci0')
            devices = scanner.scan(duration_ms=10000)  # 10 second scan
            
            # Convert to expected format
            result = []
            for dev in devices:
                hop = dev.get('hop_count', -1)
                if hop >= 0:  # Only include valid SIC devices
                    result.append({
                        'mac': dev['mac'],
                        'name': dev.get('name', 'Unknown'),
                        'hop_count': hop,
                        'rssi': dev.get('rssi', 0),
                        'nid': dev.get('nid')
                    })
                    print(f"  Found: {dev['mac']} | Hop:{hop} | RSSI:{dev.get('rssi', 0)}")
            
            # IMPORTANT: Also do a short D-Bus scan to register devices in BlueZ
            # This is needed for subsequent D-Bus Connect() calls to work
            if result:
                print("[*] Registering devices in BlueZ D-Bus...")
                try:
                    adapter = BUS.get("org.bluez", ADAPTER_PATH)
                    adapter.StartDiscovery()
                    time.sleep(2)  # Short discovery to register devices
                    adapter.StopDiscovery()
                except Exception as e:
                    print(f"[!] D-Bus registration warning: {e}")
            
            print(f"[*] Found {len(result)} SIC devices")
            return result
            
        except Exception as e:
            print(f"[!] SimplePyBLE scan error: {e}")
            print("[!] Falling back to D-Bus scan...")
            
            # Fallback to D-Bus scan
            devices = scan_nearby_devices(duration=10)
            
            result = []
            for mac, name, hop, rssi, nid in devices:
                if hop >= 0:
                    result.append({
                        'mac': mac,
                        'name': name,
                        'hop_count': hop,
                        'rssi': rssi,
                        'nid': nid
                    })
            
            print(f"[*] Found {len(result)} devices")
            return result

    def find_and_connect_uplink(self):
        print("\n--- Procurando uplink ---")

        devices = scan_nearby_devices(duration=10)
        candidates = [d for d in devices if d[2] >= 0]

        if not candidates:
            print("[!] Nenhum uplink encontrado")
            return False

        # Sort: lowest hop first (d[2]), then highest RSSI (-d[3])
        # candidates item: (mac, name, hop, rssi, nid)
        self.uplink_candidates = sorted(candidates, key=lambda d: (d[2], -d[3]))
        
        print(f"[*] Found {len(self.uplink_candidates)} candidates.")
        for i, c in enumerate(self.uplink_candidates):
            print(f"  [{i}] {c[1]} ({c[0]}) Hop={c[2]} RSSI={c[3]}")

        self.current_candidate_index = 0
        return self._try_connect_next_candidate()

    def _try_connect_next_candidate(self):
        """Helper to try connecting to the next available candidate."""
        while self.current_candidate_index < len(self.uplink_candidates):
            cand = self.uplink_candidates[self.current_candidate_index]
            mac, name, hop, rssi, nid = cand
            
            print(f"[*] Tentando candidato {self.current_candidate_index + 1}/{len(self.uplink_candidates)}: {name} {mac} (hop={hop})")
            
            if self.connect_to_device(mac):
                self.uplink_addr = mac
                self.uplink_nid = nid
                self.hop_count = hop + 1
                self.update_advertisement()

                if self.router_callback_connect:
                    self.router_callback_connect(mac, hop)
                
                return True
            else:
                print(f"[!] Falha ao conectar a {mac}. Tentando próximo...")
                self.current_candidate_index += 1
                
        print("[!] Todos os candidatos falharam.")
        self.uplink_candidates = []
        return False
    
    def failover_uplink(self):
        """Attempt to switch to the next best uplink without full rescan."""
        print("[*] Iniciando Failover de Uplink...")
        
        # Advance index to skip the one that just failed/disconnected
        self.current_candidate_index += 1
        
        if self._try_connect_next_candidate():
            print("[*] Failover bem sucedido!")
            return True
            
        print("[!] Failover falhou. Necessário novo scan.")
        return False

    # ------------------------------------------------------------------
    # Chain disconnection
    # ------------------------------------------------------------------

    def trigger_chain_disconnection(self):
        # Attempt failover first
        if self.uplink_candidates and self.current_candidate_index < len(self.uplink_candidates) - 1:
             print("[!] Perda de uplink detectada. Tentando failover...")
             if self.failover_uplink():
                 return
                 
        print("[!!!] Perda de uplink (Nível BLE) - Sem candidatos de failover")

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
