import sys
import time
from pydbus import SystemBus


BUS = SystemBus()
ADAPTER_PATH = "/org/bluez/hci0"

def scan_nearby_devices_dbus(duration=10):
    """
    Procura dispositivos usando o D-Bus (BlueZ) e as propriedades do Adaptador.
    Este método é mais estável que o PyBluez.
    """
    try:
        # Aceder ao Adaptador
        adapter = BUS.get("org.bluez", ADAPTER_PATH)
        print(f"[*] Adaptador {ADAPTER_PATH} acedido via D-Bus.")
        
        # 1. Iniciar o Discovery (Scanning)
        print(f"[*] A iniciar o scan por {duration} segundos...")
        adapter.StartDiscovery()
        
        start_time = time.time()
        discovered_devices = {}

        # 2. Esperar e monitorizar o estado (o BlueZ encontra dispositivos em background)
        while time.time() - start_time < duration:
            # Para obter os dispositivos encontrados, precisamos do ObjectManager
            obj_manager = BUS.get("org.bluez", "/")
            objects = obj_manager.GetManagedObjects()

            for path, interfaces in objects.items():
                if "org.bluez.Device1" in interfaces:
                    mac = interfaces["org.bluez.Device1"]["Address"]
                    name = interfaces["org.bluez.Device1"].get("Name", "N/A")
                    
                    if mac not in discovered_devices:
                        discovered_devices[mac] = name

            time.sleep(1)

        # 3. Parar o Discovery
        adapter.StopDiscovery()
        print("[+] Scan concluído.")

        return discovered_devices

    except Exception as e:
        print(f"[!] ERRO CRÍTICO no D-Bus Scan: {e}")
        print("[!] Solução: Certifique-se de que o adaptador está UP e tente reiniciar o BlueZ.")
        return {}


if __name__ == "__main__":
    # Garante que o hci0 existe antes de tentar correr
    try:
        adapter_props = BUS.get("org.bluez", ADAPTER_PATH).GetAll("org.bluez.Adapter1")
        print(f"[*] Nome do Adaptador: {adapter_props.get('Name')}, Endereço: {adapter_props.get('Address')}")
    except Exception as e:
        print(f"[!] Não foi possível verificar o adaptador antes do scan: {e}")
        sys.exit(1)
        
    devices = scan_nearby_devices_dbus(duration=10)
    
    if devices:
        print(f"\n[SUCESSO] Dispositivos encontrados ({len(devices)}):")
        for mac, name in devices.items():
            print(f" -> Nome: {name}, MAC: {mac}")
    else:
        print("\n[FALHA] Não encontrou dispositivos.")