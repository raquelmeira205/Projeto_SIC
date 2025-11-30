import time
from common.ble_utils import get_device_object, scan_nearby_devices

class BLEManager:
    """
    Gerencia a camada Bluetooth de um Node IoT, incluindo uplink e downlinks.
    """
    def __init__(self, node_nid):
        self.node_nid = node_nid
        # O MAC address do uplink atual
        self.uplink_addr = None 
        # Dicionário de objetos D-Bus para downlinks: {mac_addr: device_object}
        self.downlinks = {} 
        # Tabela de Encaminhamento (para o futuro: NID -> mac_addr do próximo hop)
        self.forwarding_table = {} 
        # O estado inicial do hop count é negativo, indicando que não está ligado ao Sink
        self.hop_count = -1 

    def connect_to_device(self, mac_address):
        
        device = get_device_object(mac_address)
        if not device:
            print(f"[!] Não foi possível obter o objeto do dispositivo {mac_address}.")
            return False

        try:
            print(f"[*] A tentar conectar a {mac_address}...")
            device.Connect()
            print(f"[+] Conectado com sucesso a {mac_address}.")
            
            # futura Autenticação por Certificado.
            return True
        except Exception as e:
            print(f"[!] Falha na conexão com {mac_address}: {e}")
            return False

    def disconnect_from_device(self, mac_address):
    
        device = get_device_object(mac_address)
        if not device:
            print(f"[!] Não foi possível obter o objeto do dispositivo {mac_address}.")
            return False

        try:
            print(f"[*] A tentar desconectar de {mac_address}...")
            device.Disconnect()
            print(f"[-] Desconectado com sucesso de {mac_address}.")
            return True
        except Exception as e:
            print(f"[!] Falha na desconexão com {mac_address}: {e}")
            return False

    def find_and_connect_uplink(self):
    
        print("\n--- A procurar novo Uplink ---")
        nearby_devices = scan_nearby_devices(duration=10)

        # 1. Analisar os dispositivos encontrados para encontrar um potencial uplink
        potential_uplinks = []
        for mac, name in nearby_devices:
            # Por enquanto, apenas tenta ligar ao primeiro, 
            # no futuro, será preciso obter o NID e Hop Count para a escolha.
            # print(f"Dispositivo vizinho encontrado: {name} ({mac})") 
            potential_uplinks.append(mac)

        if not potential_uplinks:
            print("[!] Nenhum dispositivo vizinho encontrado.")
            return False

        # 2. Tentar conectar-se ao primeiro dispositivo disponível (Simplificado)
        chosen_uplink_addr = potential_uplinks[0]
        if self.connect_to_device(chosen_uplink_addr):
            self.uplink_addr = chosen_uplink_addr
            # No futuro, o hop_count será estabelecido pelo heartbeat/protocolo de rede
            # self.hop_count = ?? 
            print(f"[+] Uplink estabelecido com {self.uplink_addr}.")
            return True
        
        print("[!] Não foi possível estabelecer um uplink.")
        return False


if __name__ == "__main__":
    manager = BLEManager("NID_EXEMPLO_A")
    manager.find_and_connect_uplink()
    
    # Simular uma desconexão após 5 segundos
    # if manager.uplink_addr:
    #     time.sleep(5)
    #     manager.disconnect_from_device(manager.uplink_addr)
    #     manager.uplink_addr = None
    #     manager.hop_count = -1
    #     print("Fim da simulação.")