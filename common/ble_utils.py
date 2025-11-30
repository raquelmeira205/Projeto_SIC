import bluetooth
import sys
import time
from pydbus import SystemBus


BUS = SystemBus()
try:
    # Acesso ao Adaptador (hci0 é o adaptador padrão)
    ADAPTER = BUS.get("org.bluez", "/org/bluez/hci0")
except Exception as e:
    print(f"Erro ao obter o adaptador BlueZ: {e}")
    sys.exit(1)


def scan_nearby_devices(duration=8):
    # descoberta de dispositivos 
    
    print(f"[*] A procurar dispositivos Bluetooth por {duration} segundos...")
    try:
        nearby_devices = bluetooth.discover_devices(
            duration=duration, lookup_names=True, flush_cache=True
        )

        return nearby_devices
    except bluetooth.BluetoothError as e:
        print(f"[!] Erro de Bluetooth durante o scan: {e}")
        return []

def get_device_path(mac_address):
    # caminho para dispositivo

    return "/org/bluez/hci0/dev_" + mac_address.replace(":", "_")

def get_device_object(mac_address):
    device_path = get_device_path(mac_address)  # mac do dispositivo
    try:
        
        return BUS.get("org.bluez", device_path)
    except Exception as e:
        print(f"[!] Erro ao obter objeto D-Bus para {mac_address}: {e}")
        return None