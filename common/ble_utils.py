import sys
import time
from pydbus import SystemBus

BUS = SystemBus()

def find_adapter(bus):
    try:
        remote_om = bus.get("org.bluez", "/")
        objects = remote_om.GetManagedObjects()
        for path, interfaces in objects.items():
            if "org.bluez.Adapter1" in interfaces:
                print(f"[BLE] Using adapter: {path}")
                return path
        print("[!] No bluetooth adapter found. Defaulting to /org/bluez/hci0")
        return "/org/bluez/hci0"
    except Exception as e:
        print(f"[!] Error finding adapter: {e}")
        return "/org/bluez/hci0"

ADAPTER_PATH = find_adapter(BUS)

# UUIDs do Projeto SIC
SIC_SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
SIC_RX_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef1"

def get_device_path(mac_address):
    return ADAPTER_PATH + "/dev_" + mac_address.replace(":", "_")

def get_device_object(mac_address):
    device_path = get_device_path(mac_address)
    try:
        # Obtém o objeto D-Bus do dispositivo remoto
        return BUS.get("org.bluez", device_path)
    except Exception as e:
        print(f"[!] Erro ao obter objeto D-Bus para {mac_address}: {e}")
        return None

def get_gatt_characteristic(mac_address, uuid):
    """Encotra o objeto D-Bus da característica com o UUID específico no dispositivo."""
    device_path = get_device_path(mac_address)
    try:
        obj_manager = BUS.get("org.bluez", "/")
        objects = obj_manager.GetManagedObjects()
        
        for path, interfaces in objects.items():
            if "org.bluez.GattCharacteristic1" in interfaces:
                if path.startswith(device_path):
                    props = interfaces["org.bluez.GattCharacteristic1"]
                    if props.get("UUID") == uuid:
                         return BUS.get("org.bluez", path)
        print(f"[!] Característica {uuid} não encontrada em {mac_address}.")
        
        # Enhanced Debugging: List all available characteristics for this device
        print(f"[DEBUG] Características disponíveis em {mac_address}:")
        for path, interfaces in objects.items():
             if "org.bluez.GattCharacteristic1" in interfaces:
                 if path.startswith(device_path):
                     props = interfaces["org.bluez.GattCharacteristic1"]
                     c_uuid = props.get("UUID")
                     print(f"   - {c_uuid} @ {path}")

        return None
    except Exception as e:
        print(f"[!] Erro ao procurar característica GATT: {e}")
        return None


def scan_nearby_devices(duration=10):
    """Procura dispositivos, extraindo nome, MAC, RSSI e o Hop Count anunciado.
    Retorna uma lista de tuplos: (mac, name, hop_count, rssi)"""
    try:
        adapter = BUS.get("org.bluez", ADAPTER_PATH)
        
        # Discovery
        adapter.StartDiscovery()
        discovered_devices_metrics = {}
        
        print(f"[*] A iniciar scan D-Bus por {duration}s...") # Feedback visual

        # Esperar e monitorizar o estado
        start_time = time.time()
        while time.time() - start_time < duration:
            obj_manager = BUS.get("org.bluez", "/")
            objects = obj_manager.GetManagedObjects()

            for path, interfaces in objects.items():
                if "org.bluez.Device1" in interfaces:
                    device_props = interfaces["org.bluez.Device1"]
                    mac = device_props["Address"]
                    name = device_props.get("Name", "N/A")
                    
                    # rssi
                    rssi = device_props.get("RSSI", -100)

                    # lista de tudo o que aparece
                    print(f"[DEBUG] Python viu: {mac} | Nome: {name} | RSSI: {rssi}")
                    # ----------------------------------------------------

                    hop_count = -1 # Valor padrão, significa 'não conectado ao Sink'

                    manufacturer_data = device_props.get("ManufacturerData", {})
                    
                    # DEBUG: Print raw manufacturer data
                    if manufacturer_data:
                         print(f"       [DEBUG-MD] ManufData para {mac}: {manufacturer_data}")

                    CUSTOM_ADV_ID = 0xFFFE

                    nid = None
                    if CUSTOM_ADV_ID in manufacturer_data:
                        adv_data = manufacturer_data[CUSTOM_ADV_ID]
                        # o primeiro byte é o hop count
                        if len(adv_data) > 1:
                            hop_count = adv_data[0]
                            nid = bytes(adv_data[1:])
                    elif name and name.startswith("SIC-"):
                        # Fallback: Se não temos manufacturer data mas o nome é SIC-Sink ou SIC-Node
                        # Assume hop count 0 para Sink, 255 para desconhecido
                        if "Sink" in name:
                            hop_count = 0
                            print(f"       [FALLBACK] Detected SIC device by name: {name}")
                        else:
                            hop_count = 255
                            print(f"       [FALLBACK] Detected SIC device by name: {name}")
                    
                    # Lógica de atualização: Se é novo ou se o sinal melhorou
                    if mac not in discovered_devices_metrics or rssi > discovered_devices_metrics[mac]['rssi']:
                        discovered_devices_metrics[mac] = {
                            "name": name,
                            "hop_count": hop_count,
                            "rssi": rssi,
                            "nid": nid
                        }

            time.sleep(1)
        
        # Parar o Discovery
        adapter.StopDiscovery()

        return [
            (mac, data['name'], data['hop_count'], data['rssi'], data['nid'])
            for mac, data in discovered_devices_metrics.items()
        ]

    except Exception as e:
        print(f"[!] ERRO CRÍTICO no D-Bus Scan: {e}")
        return []