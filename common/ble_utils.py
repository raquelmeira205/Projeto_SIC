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
                    CUSTOM_ADV_ID = 0xFFFE

                    if CUSTOM_ADV_ID in manufacturer_data:
                        adv_data = manufacturer_data[CUSTOM_ADV_ID]
                        # o primeiro byte é o hop count
                        if len(adv_data) > 0:
                            hop_count = adv_data[0]
                    
                    # Lógica de atualização: Se é novo ou se o sinal melhorou
                    if mac not in discovered_devices_metrics or rssi > discovered_devices_metrics[mac]['rssi']:
                        discovered_devices_metrics[mac] = {
                            "name": name,
                            "hop_count": hop_count,
                            "rssi": rssi
                        }

            time.sleep(1)
        
        # Parar o Discovery
        adapter.StopDiscovery()

        return [
            (mac, data['name'], data['hop_count'], data['rssi'])
            for mac, data in discovered_devices_metrics.items()
        ]

    except Exception as e:
        print(f"[!] ERRO CRÍTICO no D-Bus Scan: {e}")
        return []