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
    
        print("\n--- A procurar novo Uplink (Otimizado) ---")
        
        # CORREÇÃO: Usar uma variável para armazenar o resultado do scan
        # ASSUMIR que 'scan_nearby_devices' retorna: (mac, name, hop_count, rssi)
        nearby_devices_data = scan_nearby_devices(duration=10)

        # 1. Analisar os dispositivos encontrados e aplicar a lógica de seleção
        potential_uplinks = []
        # O loop agora usa a variável definida na linha anterior
        for mac, name, hop_count, rssi in nearby_devices_data:
            # Filtro: Apenas considera nós que já anunciam uma rota (hop_count >= 0)
            if hop_count >= 0:
                potential_uplinks.append({
                    "mac": mac,
                    "name": name,
                    "hop_count": hop_count,
                    "rssi": rssi  # RSSI é negativo, maior valor é melhor sinal
                })

        if not potential_uplinks:
            print("[!] Nenhum dispositivo vizinho elegível encontrado.")
            return False

        # 2. Lógica de Uplink Otimizada: Menor Hop Count -> Melhor RSSI
        
        # Inicializar a melhor escolha com o primeiro candidato
        best_uplink = potential_uplinks[0]

        # Iterar para encontrar o melhor nó
        for uplink in potential_uplinks[1:]:
            
            # CRITÉRIO PRIMÁRIO: Menor Hop Count é prioridade
            if uplink['hop_count'] < best_uplink['hop_count']:
                best_uplink = uplink
                
            # CRITÉRIO SECUNDÁRIO: Se o Hop Count for igual, escolher o melhor RSSI
            elif uplink['hop_count'] == best_uplink['hop_count']:
                if uplink['rssi'] > best_uplink['rssi']:
                    best_uplink = uplink

        # 3. Tentar conectar-se ao dispositivo escolhido
        chosen_uplink_addr = best_uplink['mac']
        
        print(f"[*] Melhor Uplink escolhido: {best_uplink['name']} ({chosen_uplink_addr})")
        print(f"    Métricas: Hop Count = {best_uplink['hop_count']}, RSSI = {best_uplink['rssi']} dBm")

        if self.connect_to_device(chosen_uplink_addr):
            # O Hop Count do nó local é o do vizinho + 1
            self.hop_count = best_uplink['hop_count'] + 1
            self.uplink_addr = chosen_uplink_addr
            print(f"[+] Uplink estabelecido com {self.uplink_addr}.")
            print(f"[#] Meu novo Hop Count é: {self.hop_count}")
            return True
        
        print("[!] Não foi possível estabelecer um uplink com o nó otimizado.")
        return False