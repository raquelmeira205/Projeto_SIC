import simplepyble


class BLEDiscovery:
    """
    Classe Wrapper para o SimplePyBLE, utilizada para realizar varreduras de dispositivos BLE.
    """
    
    def __init__(self, adapter_name='hci0'):
        """
        Inicializa o scanner BLE.
        
        :param adapter_name: Nome do adaptador BLE (ex: 'hci0').
        """
        self.adapter_name = adapter_name
        self.adapter = None
        
        adapters = simplepyble.Adapter.get_adapters()
        
        if not adapters:
            raise RuntimeError("Nenhum adaptador BLE encontrado")
        
        self.adapter = adapters[0]
        # print(f"[BLEDiscovery] Usando adaptador: {self.adapter.identifier()} [{self.adapter.address()}]")
    
    def scan(self, duration_ms=10000):
        """
        Realiza uma varredura por dispositivos BLE.
        
        :param duration_ms: Duração da varredura em milissegundos.
        :return: Lista de dispositivos encontrados com suas informações (MAC, nome, RSSI, Hop Count, NID).
        """
        if not self.adapter:
            raise RuntimeError("Adaptador não inicializado")
        
        self.adapter.scan_for(duration_ms)
        
        peripherals = self.adapter.scan_get_results()
        
        devices = []
        for peripheral in peripherals:
            device_info = {
                'mac': peripheral.address(),
                'name': peripheral.identifier(),
                'rssi': peripheral.rssi() if hasattr(peripheral, 'rssi') else 0,
                'hop_count': -1,
                'nid': None
            }
            
            manufacturer_data = peripheral.manufacturer_data()
            
            for company_id, data in manufacturer_data.items():
                if company_id == 0xFFFE and len(data) >= 17:
                    device_info['hop_count'] = data[0]
                    device_info['nid'] = bytes(data[1:17])
                    break
            
            devices.append(device_info)
        
        return devices
