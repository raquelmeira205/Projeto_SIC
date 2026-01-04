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
    """
    Gerencia as operações de Bluetooth Low Energy (BLE) para o nó, incluindo publicidade,
    conexões com outros dispositivos (uplink/downlink) e envio de pacotes GATT.
    """

    def __init__(self, node_nid: bytes):
        """
        Inicializa o gerenciador BLE.

        :param node_nid: ID do nó (Network ID) em bytes.
        """
        self.node_nid = node_nid

        self.uplink_addr = None
        self.uplink_nid = None
        self.downlinks = {}
        self.forwarding_table = {}

        self.hop_count = -1
        self.advertisement = None

        self.router_callback_connect = None
        self.router_callback_disconnect = None
        
        self.uplink_candidates = []
        self.current_candidate_index = 0

        self.adv_index = node_nid[-1]

    def set_router_callbacks(self, on_connect, on_disconnect):
        """
        Define os callbacks para eventos de conexão e desconexão do roteador.

        :param on_connect: Função a ser chamada quando uma conexão é estabelecida.
        :param on_disconnect: Função a ser chamada quando uma conexão é perdida.
        """
        self.router_callback_connect = on_connect
        self.router_callback_disconnect = on_disconnect

    def start_advertising(self):
        """
        Inicia a publicidade BLE do nó.
        O payload de publicidade inclui a contagem de saltos (hop count) e o NID do nó.
        """
        if self.advertisement:
            return

        self.advertisement = Advertisement(
            BUS,
            index=self.adv_index,
            advertising_type="peripheral"
        )

        hc = self.hop_count if self.hop_count >= 0 else 0xFF
        payload = bytes([hc]) + self.node_nid
        
        self.advertisement.add_manufacturer_data(0xFFFE, payload)

        try:
            self.advertisement.register(ADAPTER_PATH)
        except Exception as e:
            print(f"[!] Falha ao iniciar Advertisement: {e}")
            self.advertisement = None

    def update_advertisement(self):
        """
        Atualiza os dados de publicidade (por exemplo, quando o hop count muda).
        Para e reinicia o advertisement com os novos dados.
        """
        if self.advertisement:
            try:
                self.advertisement.unregister(ADAPTER_PATH)
            except Exception:
                pass
            self.advertisement = None

        self.start_advertising()

    def send_packet(self, dest_mac, packet):
        """
        Envia um pacote de dados para um dispositivo de destino via GATT.
        Tenta conectar se não estiver conectado e aguarda a descoberta de serviços.

        :param dest_mac: Endereço MAC do destino.
        :param packet: Dados do pacote a serem enviados.
        :return: True se enviado com sucesso, False caso contrário.
        """
        device = get_device_object(dest_mac)

        if not device or not device.Connected:
            if not self.connect_to_device(dest_mac):
                return False

        try:
            if not device.ServicesResolved:
                if not get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID):
                    import time
                    for i in range(20):
                        time.sleep(0.1)
                        if device.ServicesResolved or get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID):
                            break
        except:
            pass

        char = get_gatt_characteristic(dest_mac, SIC_RX_CHAR_UUID)
        if not char:
            return False

        max_retries = 3
        for attempt in range(max_retries):
            try:
                char.WriteValue(packet, {})
                return True
            except Exception as e:
                err_str = str(e)
                if "InProgress" in err_str or "Busy" in err_str:
                     import time
                     time.sleep(0.2)
                     continue
                
                if "NotConnected" in err_str:
                    break
        
        return False

    def write_value(self, mac, data):
        """
        Wrapper para enviar dados para um endereço MAC específico.

        :param mac: Endereço MAC do destino.
        :param data: Dados a serem escritos.
        :return: Resultado de send_packet.
        """
        return self.send_packet(mac, data)

    def connect_to_device(self, mac):
        """
        Estabelece uma conexão BLE com um dispositivo específico.
        Tenta usar o método ConnectDevice do BlueZ para conexões LE, com fallback para Connect padrão.

        :param mac: Endereço MAC do dispositivo.
        :return: True se conectado com sucesso, False caso contrário.
        """
        import time
        from gi.repository import GLib
        
        max_wait = 5
        device = None
        for i in range(max_wait):
            device = get_device_object(mac)
            if device:
                break
            time.sleep(1)
        
        if not device:
            print(f"[!] Dispositivo {mac} não encontrado no D-Bus")
            return False

        try:
            if hasattr(device, 'Connected') and device.Connected:
                return True
            
            connection_initiated = False
            try:
                adapter = BUS.get("org.bluez", ADAPTER_PATH)['org.bluez.Adapter1']
                properties = {
                    'Address': GLib.Variant('s', mac),
                    'AddressType': GLib.Variant('s', 'public')
                }
                adapter.ConnectDevice(properties)
                connection_initiated = True
            except Exception:
                try:
                    device.Connect()
                    connection_initiated = True
                except Exception as e2:
                    if 'InProgress' in str(e2) or 'busy' in str(e2).lower():
                        connection_initiated = True
                    else:
                        print(f"[!] Connect falhou: {e2}")
            
            if not connection_initiated:
                return False
            
            for i in range(15):
                time.sleep(0.5)
                device = get_device_object(mac)
                if device and hasattr(device, 'Connected') and device.Connected:
                    self.update_advertisement()
                    return True
            
            device = get_device_object(mac)
            if device and hasattr(device, 'Connected') and device.Connected:
                self.update_advertisement()
                return True
            
            return False
            
        except Exception as e:
            print(f"[!] Erro conexão {mac}: {e}")
            return False

    def disconnect_from_device(self, mac):
        """
        Desconecta de um dispositivo BLE.

        :param mac: Endereço MAC do dispositivo.
        :return: True se desconectado com sucesso (ou tentativa feita), False caso contrário.
        """
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

    def scan_for_devices(self):
        """
        Realiza uma varredura manual por dispositivos BLE próximos.
        Usa simplepyble se disponível, ou fallback para scan D-Bus padrão.
        Filtra apenas dispositivos válidos do projeto (SIC).

        :return: Lista de dicionários contendo informações dos dispositivos encontrados.
        """
        try:
            from node.ble_discovery import BLEDiscovery
            import time
            
            scanner = BLEDiscovery('hci0')
            devices = scanner.scan(duration_ms=10000)
            
            result = []
            for dev in devices:
                hop = dev.get('hop_count', -1)
                if hop >= 0:
                    result.append({
                        'mac': dev['mac'],
                        'name': dev.get('name', 'Unknown'),
                        'hop_count': hop,
                        'rssi': dev.get('rssi', 0),
                        'nid': dev.get('nid')
                    })
            
            if result:
                try:
                    adapter = BUS.get("org.bluez", ADAPTER_PATH)
                    adapter.StartDiscovery()
                    time.sleep(2)
                    adapter.StopDiscovery()
                except Exception as e:
                    print(f"[!] Aviso registro D-Bus: {e}")
            
            return result
            
        except Exception as e:
            print(f"[!] Erro SimplePyBLE, usando fallback: {e}")
            
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
            
            return result

    def find_and_connect_uplink(self):
        """
        Procura por um uplink adequado entre os dispositivos próximos e tenta conectar.
        Prioriza dispositivos com menor hop count e melhor sinal (RSSI).

        :return: True se conectar a um uplink, False caso contrário.
        """
        devices = scan_nearby_devices(duration=10)
        candidates = [d for d in devices if d[2] >= 0]

        if not candidates:
            return False

        self.uplink_candidates = sorted(candidates, key=lambda d: (d[2], -d[3]))
        
        self.current_candidate_index = 0
        return self._try_connect_next_candidate()

    def _try_connect_next_candidate(self):
        """
        Método auxiliar para tentar conectar ao próximo candidato da lista de uplinks.
        
        :return: True se conectado com sucesso, False se todos falharem.
        """
        while self.current_candidate_index < len(self.uplink_candidates):
            cand = self.uplink_candidates[self.current_candidate_index]
            mac, name, hop, rssi, nid = cand
            
            if self.connect_to_device(mac):
                self.uplink_addr = mac
                self.uplink_nid = nid
                self.hop_count = hop + 1
                self.update_advertisement()

                if self.router_callback_connect:
                    self.router_callback_connect(mac, hop)
                
                return True
            else:
                self.current_candidate_index += 1
                
        self.uplink_candidates = []
        return False
    
    def failover_uplink(self):
        """
        Tenta alternar para o próximo melhor uplink sem realizar uma nova varredura completa.
        Utilizado quando o uplink atual falha.

        :return: True se o failover for bem-sucedido, False caso contrário.
        """
        self.current_candidate_index += 1
        
        if self._try_connect_next_candidate():
            return True
            
        return False

    def trigger_chain_disconnection(self):
        """
        Trata a desconexão do uplink.
        Tenta realizar failover para outro candidato. Se falhar, reseta o estado de uplink e hop count.
        """
        if self.uplink_candidates and self.current_candidate_index < len(self.uplink_candidates) - 1:
             if self.failover_uplink():
                 return
                 
        print("[!] Perda de uplink confirmada - Sem failover possível")

        self.uplink_addr = None
        self.uplink_nid = None
        self.hop_count = -1

        self.update_advertisement()

    def monitor_connection_status(self):
        """
        Monitora periodicamente o status da conexão com o uplink.
        Aciona a lógica de desconexão se o uplink não estiver mais conectado.
        """
        if not self.uplink_addr:
            return

        try:
            device = get_device_object(self.uplink_addr)
            if not device or not device.Connected:
                self.trigger_chain_disconnection()
        except Exception:
             self.trigger_chain_disconnection()
