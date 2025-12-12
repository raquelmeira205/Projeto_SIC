import time
import simplepyble
from common.ble_utils import get_simplepyble_device, scan_nearby_devices
from common.constants import SERVICE_UUID, CHARACTERISTIC_UUID
from node.gatt_server import NodeGATTServer
import threading


class BLEManager:
   
    def __init__(self, node_nid, packet_handler_cb=None):
        self.node_nid = node_nid
        self.uplink_addr = None 
        # Dict of {mac_addr: simplepyble.Peripheral}
        self.connected_devices = {} 
        self.forwarding_table = {} 
        self.hop_count = -1 
        
        # GATT Server
        self.gatt_server = NodeGATTServer(packet_handler_cb)
        
        # Start GATT in a separate thread/loop async if needed, 
        # but DBus mainloop usually runs in the main thread.
        # Ideally, we should have a `run()` method for the node that starts the DBus loop.
        # checking how existing code runs...
        # For now, we instantiate it. Start() must be called.


    def connect_to_device(self, mac_address):
        # Using simplepyble
        device = get_simplepyble_device(mac_address)
        if not device:
            print(f"[!] Dispositivo {mac_address} não encontrado em scan recente. Tentando rescan...")
            # Optional: quick rescan or assume caller just scanned
            return False

        try:
            print(f"[*] A tentar conectar a {mac_address} via simplepyble...")
            device.connect()
            print(f"[+] Conectado com sucesso a {mac_address}.")
            
            # Store in connected devices
            self.connected_devices[mac_address] = device
            
            # Subscribe to Notifications (Downstream Data from Uplink)
            try:
                # Need to find the characteristic first? 
                # simplepyble caches services.
                # Subscribe: device.notify(service, char, callback)
                # Callback signature: (data) -> None
                
                device.notify(SERVICE_UUID, CHARACTERISTIC_UUID, self._on_notification_received)
                print(f"[*] Subscrito a notificações de {mac_address}.")
            except Exception as e:
                print(f"[!] Aviso: Falha ao subscrever notificações de {mac_address}: {e}")
                # Don't fail connection just because notify failed, but it's critical for downstream.
            
            return True
        except Exception as e:
            print(f"[!] Falha na conexão com {mac_address}: {e}")
            return False

    def _on_notification_received(self, data):
        """
        Callback for notifications received from Uplink (or others).
        data: bytes
        """
        # Pass to GATT Server packet handler logic.
        # Data comes from Uplink. connection handle = self.uplink_addr
        if self.gatt_server.packet_handler:
            self.gatt_server.packet_handler(data, self.uplink_addr)



    def disconnect_from_device(self, mac_address):
        if mac_address in self.connected_devices:
            device = self.connected_devices[mac_address]
            try:
                print(f"[*] A tentar desconectar de {mac_address}...")
                device.disconnect()
                print(f"[-] Desconectado com sucesso de {mac_address}.")
                del self.connected_devices[mac_address]
                return True
            except Exception as e:
                print(f"[!] Falha na desconexão com {mac_address}: {e}")
                return False
        else:
            print(f"[!] {mac_address} não está na lista de conectados.")
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

            print(f"[+] Uplink estabelecido com {self.uplink_addr}.")
            # Update local Hop Count 
            self.hop_count = best_uplink['hop_count'] + 1
            print(f"[#] Meu novo Hop Count é: {self.hop_count}")
            
            # Update Advertisement
            self.gatt_server.update_hop_count(self.hop_count)
            
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
        
        # Desconecta os filhos (Downlinks)
        downlink_macs = list(self.connected_devices.keys())
        # Filter out uplink if it's there (it shouldn't be if we just disconnected, but check)
        
        if downlink_macs:
            print(f"[Action] A derrubar {len(downlink_macs)} conexões restantes...")
            for child_mac in downlink_macs:
                if child_mac != previous_uplink: # Don't try to disconnect the uplink we just lost
                    print(f"   -> Desconectando: {child_mac}")
                    self.disconnect_from_device(child_mac)
        
        # Reset Advertise to 'Disconnected' (-1 or 255)
        self.gatt_server.update_hop_count(-1)
        
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
                
    def send_packet(self, mac_address, packet_bytes):
        """
        Envia bytes para a Characteristic UUID.
        Se mac_address for Uplink -> Write Request.
        Se mac_address for outro (Downlink) -> Notification Broadcast.
        """
        if mac_address == self.uplink_addr and mac_address in self.connected_devices:
            # Uplink
            device = self.connected_devices[mac_address]
            try:
                device.write_request(SERVICE_UUID, CHARACTERISTIC_UUID, packet_bytes)
                return True
            except Exception as e:
                print(f"[TX FAIL] Erro ao enviar para Uplink {mac_address}: {e}")
                return False
        else:
            # Check if it's a known Downlink? 
            # actually we just broadcast downstream for now as discussed.
            # We assume it is a downlink if we are asked to send to it and it's not the uplink.
            try:
                self.gatt_server.send_notification(packet_bytes)
                return True
            except Exception as e:
                 print(f"[TX FAIL] Erro ao notificar (broadcast): {e}")
                 return False

    def send_downstream(self, packet_bytes):
        """
        Broadcasts packet to all connected downlinks via Notifications.
        """
        try:
            self.gatt_server.send_notification(packet_bytes)
            return True
        except Exception as e:
            print(f"[TX FAIL] Broadcast error: {e}")
            return False

    def send_to_all_links(self, packet_bytes):
        """
        Envia para Uplink (Unicast) e Downlinks (Broadcast).
        """
        success_count = 0
        
        # 1. Send to Uplink (if connected)
        if self.uplink_addr:
             if self.send_packet(self.uplink_addr, packet_bytes):
                 success_count += 1
                 
        # 2. Send to Downlinks (Broadcast)
        if self.send_downstream(packet_bytes):
            success_count += 1
        
        return success_count