import sys
import time
from pydbus import SystemBus

BUS = SystemBus()
ADAPTER_PATH = "/org/bluez/hci0"

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


def scan_nearby_devices(duration=10):
    """Procura dispositivos usando o D-Bus (BlueZ). Mais estável que PyBluez."""
    try:
        adapter = BUS.get("org.bluez", ADAPTER_PATH)
        
        # Discovery
        adapter.StartDiscovery()
        discovered_devices = {}
        
        # Esperar e monitorizar o estado
        start_time = time.time()
        while time.time() - start_time < duration:
            obj_manager = BUS.get("org.bluez", "/")
            objects = obj_manager.GetManagedObjects()

            for path, interfaces in objects.items():
                if "org.bluez.Device1" in interfaces:
                    mac = interfaces["org.bluez.Device1"]["Address"]
                    name = interfaces["org.bluez.Device1"].get("Name", "N/A")
                    
                    if mac not in discovered_devices:
                        discovered_devices[mac] = name
            time.sleep(1)

        # Parar o Discovery
        adapter.StopDiscovery()
        
        # Retorna a lista de tuplos [(mac, nome)] que o BLEManager espera
        return [(mac, name) for mac, name in discovered_devices.items()]

    except Exception as e:
        print(f"[!] ERRO CRÍTICO no D-Bus Scan: {e}")
        return []