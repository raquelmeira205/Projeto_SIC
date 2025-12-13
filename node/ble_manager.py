import time
from gi.repository import GLib
from common.ble_utils import get_device_object, scan_nearby_devices, BUS, SIC_RX_CHAR_UUID, get_gatt_characteristic, SIC_SERVICE_UUID
from common.bluez_classes import Advertisement

class BLEManager:
   
    def __init__(self, node_nid):
        self.node_nid = node_nid
        # O MAC address do uplink atual
        self.uplink_addr = None 
        # Dicionário de objetos D-Bus para downlinks: {mac_addr: device_object}
        self.downlinks = {} 
        # Tabela de Encaminhamento (para o futuro: NID -> mac_addr do próximo hop)
        self.forwarding_table = {} 
        # O estado inicial do hop count é negativo, indicando que não está ligado ao Sink
        # O estado inicial do hop count é negativo, indicando que não está ligado ao Sink
        self.hop_count = -1 
        self.advertisement = None
        self.router_callback_connect = None
        self.router_callback_disconnect = None

    def set_router_callbacks(self, on_connect, on_disconnect):
        self.router_callback_connect = on_connect
        self.router_callback_disconnect = on_disconnect

    def start_advertising(self):
        if self.advertisement:
            return # Já está a anunciar
            
        print(f"[*] A iniciar Advertisement (Hop Count={self.hop_count})...")
        # Criar instância de Advertisement (type='peripheral')
        self.advertisement = Advertisement(BUS, 0, 'peripheral')
        
        # Nome local: "Node-<4 bytes do NID>"
        local_name = f"Node-{self.node_nid[-4:].hex()}"
        self.advertisement.add_local_name(local_name)
        
        # Adicionar UUID do serviço principal para que os outros saibam que somos um nó SIC
        self.advertisement.add_service_uuid(SIC_SERVICE_UUID)
        
        # Manufacturer Data: [Hop Count (1 byte)] + [NID (16 bytes)]
        # Se hop_count for -1, enviamos 255 (0xFF)
        hc_val = self.hop_count if self.hop_count >= 0 else 0xFF
        
        # Criar payload
        manuf_payload = [hc_val] + list(self.node_nid)
        self.advertisement.add_manufacturer_data(0xFFFE, manuf_payload)
        
        try:
            self.advertisement.register()
        except Exception as e:
            print(f"[!] Falha ao registar Advertisement: {e}")
            self.advertisement = None

    def update_advertisement(self):
        """Atualiza os dados de manufatura (ex: hop count mudou)."""
        if self.advertisement:
            print("[*] A atualizar Advertisement com novo Hop Count...")
            self.advertisement.unregister()
            self.advertisement = None
            
        self.start_advertising()

    def send_packet(self, dest_mac, packet_data):
        """Envia pacote via GATT Write no destinatário."""
        device = get_device_object(dest_mac)
        
        # 1. Garantir conexão
        if not device or not device.Connected:
            if not self.connect_to_device(dest_mac):
                return False
                
        # 2. Obter a Característica RX do destino
        char_proxy = get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID)
        if not char_proxy:
            print(f"[!] Não foi possível encontrar a característica RX em {dest_mac}")
            return False
            
        # 3. Escrever (WriteValue)
        try:
            # WriteValue(value, options). Value deve ser bytes.
            # pydbus/bluez requerem, por vezes, array de bytes. O proxy do pydbus lida com conversão base, 
            # mas 'ay' DBus type mapeia para bytes em Python 3.
            char_proxy.WriteValue(packet_data, {'type': GLib.Variant('s', 'command')}) 
            # Note: 'type': 'command' -> Write Without Response, 'request' -> Write With Response.
            # Se quisermos garantia, usamos 'request'. Padrão é 'request' se omitido geralmente, mas depende da char properties.
            # Vou assumir default options {} que é WriteWithResponse se suportado.
            return True
        except Exception as e:
            print(f"[!] Erro ao enviar pacote para {dest_mac}: {e}")
            return False

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

    def disconnect(self, mac_address):
        """Alias compatível com router.py"""
        return self.disconnect_from_device(mac_address)

    def disconnect_from_device(self, mac_address):
    
        device = get_device_object(mac_address)
        if not device:
            print(f"[!] Não foi possível obter o objeto do dispositivo {mac_address}.")
            return False

        try:
            print(f"[*] A tentar desconectar de {mac_address}...")
            device.Disconnect()
            print(f"[-] Desconectado com sucesso de {mac_address}.")
            
            # Se desconectámos o uplink explicitamente (ou pedido pelo router)
            if mac_address == self.uplink_addr:
                 self.trigger_chain_disconnection()
            
            # Notificar router se necessário
            if self.router_callback_disconnect:
                self.router_callback_disconnect(mac_address)
                
            return True
        except Exception as e:
            print(f"[!] Falha na desconexão com {mac_address}: {e}")
            return False

    def find_and_connect_uplink(self):
    
        print("\n--- A procurar novo Uplink (Otimizado) ---")
        
        # scan_nearby_devices' retorna: (mac, name, hop_count, rssi)
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
            
            # Atualizar advertisement para refletir novo hop count
            self.update_advertisement()
            
            # Notificar Router
            if self.router_callback_connect:
                self.router_callback_connect(self.uplink_addr, best_uplink['hop_count'])
                
            return True
        
        print("[!] Não foi possível estabelecer um uplink com o nó otimizado.")
        return False


    def trigger_chain_disconnection(self):
        """
        Executa a lógica de 'Chain Disconnection'
        """
        print(f"\n[!!!] CRÍTICO: Perda de Uplink ({self.uplink_addr}) detetada!")
        
        previous_uplink = self.uplink_addr
        self.uplink_addr = None
        self.hop_count = -1
        
        # Desconecta os filhos
        downlink_macs = list(self.downlinks.keys())
        if downlink_macs:
            print(f"[Action] A derrubar {len(downlink_macs)} downlinks...")
            for child_mac in downlink_macs:
                print(f"   -> Desconectando filho: {child_mac}")
                self.disconnect_from_device(child_mac)
                del self.downlinks[child_mac]
        
        print(f"[SUCESSO] Nó desconectado de {previous_uplink}. Reiniciando...") 



    def monitor_connection_status(self):
        """
        Verifica se o Uplink atual ainda está conectado.
        Deve ser chamado periodicamente pelo sistema principal.
        """
        if self.uplink_addr:
            device = get_device_object(self.uplink_addr)
            
            # Se não conseguimos obter o objeto ou a propriedade 'Connected' for False
            # Nota: Dependendo da lib D-Bus, pode ser device.Connected ou device.Get(..., "Connected")
            try:
                is_connected = device.Connected 
            except:
                is_connected = False
            
            if not is_connected:
                print(f"[Alert] O Uplink {self.uplink_addr} deixou de responder.")
                self.trigger_chain_disconnection()


      