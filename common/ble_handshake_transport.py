"""
Adaptador de Transporte BLE para Handshake de Segurança.

Este módulo fornece uma camada de transporte que adapta operações de leitura/escrita
de características BLE GATT para funcionar com o protocolo SecurityHandshake.
"""

import time
from gi.repository import GLib
from common.ble_utils import get_gatt_characteristic, SIC_RX_CHAR_UUID

MAX_CHUNK_SIZE = 100

class BLEHandshakeTransport:
    """
    Adaptador de transporte para realizar handshake de segurança sobre BLE GATT.
    Envolve operações de características GATT para fornecer métodos send() e receive().
    """
    
    def __init__(self, mac_address, ble_manager, is_initiator=True, timeout=10.0):
        """
        Inicializa o transporte de handshake BLE.
        
        :param mac_address: Endereço MAC do dispositivo par.
        :param ble_manager: Instância BLEManager para envio de pacotes.
        :param is_initiator: True se este lado inicia o handshake.
        :param timeout: Timeout em segundos para operações de recepção.
        """
        self.mac = mac_address
        self.ble_manager = ble_manager
        self.is_initiator = is_initiator
        self.timeout = timeout
        self.receive_buffer = []
        self.receive_complete = False
        
    def send(self, data):
        """
        Envia dados sobre BLE usando o método send_packet do gerenciador BLE.
        Os dados são fragmentados devido às limitações de MTU do BLE.
        
        :param data: Bytes a enviar.
        """
        if not isinstance(data, bytes):
            raise TypeError("Dados devem ser bytes")
        
        total_length = len(data)
        num_chunks = (total_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        
        print(f"[Handshake-TX] Enviando {total_length} bytes em {num_chunks} pedaços para {self.mac}")
        
        for i in range(num_chunks):
            start = i * MAX_CHUNK_SIZE
            end = min(start + MAX_CHUNK_SIZE, total_length)
            chunk_data = data[start:end]
            
            # Frame: [0xFF marker][total_length][chunk_index][chunk_data]
            frame = (
                b'\xFF' +
                total_length.to_bytes(4, 'big') +
                i.to_bytes(2, 'big') +
                chunk_data
            )
            
            sucesso = False
            tentativas = 3
            while not sucesso and tentativas > 0:
                try:
                    if self.ble_manager.write_value(self.mac, frame):
                        sucesso = True
                    else:
                        print(f"[Transport] write_value retornou False no pedaço {i}")
                    
                    time.sleep(0.15) 
                    
                except Exception as e:
                    print(f"[Transport] Falha no pedaço {i}, tentando novamente... ({e})")
                    tentativas -= 1
                    time.sleep(0.5) 
            
            if not sucesso:
                raise ConnectionError(f"Falha fatal ao enviar pedaço {i} após 3 tentativas")
        
        print(f"[Handshake-TX] Enviados {num_chunks} pedaços com sucesso")
    
    def receive(self):
        """
        Recebe dados pela característica BLE GATT.
        Bloqueante até que os dados cheguem ou ocorra timeout.
        
        :return: Dados recebidos (bytes).
        """
        print(f"[Handshake-RX] Aguardando dados de {self.mac}")
        
        expected_length = None
        
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            if self.receive_buffer:
                if expected_length is None and self.receive_buffer:
                    expected_length = self.receive_buffer[0][0]
                
                matching_chunks = [c for c in self.receive_buffer if c[0] == expected_length]
                
                data = self._reassemble_chunks_filtered(matching_chunks, expected_length)
                if data is not None:
                    print(f"[Handshake-RX] Recebidos {len(data)} bytes")
                    self.receive_buffer = [c for c in self.receive_buffer if c[0] != expected_length]
                    return data
            time.sleep(0.1)
        
        raise TimeoutError(f"Timeout aguardando dados de {self.mac}")
    
    def _reassemble_chunks_filtered(self, chunks, expected_length):
        """Re monta pedaços filtrados para um comprimento esperado específico."""
        if not chunks:
            return None
        
        chunks = sorted(chunks, key=lambda x: x[1])
        
        expected_chunks = (expected_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        
        if len(chunks) < expected_chunks:
            return None 
        
        data = b''.join(chunk[2] for chunk in chunks)
        
        return data[:expected_length]
    
    def _reassemble_chunks(self):
        """Remonta pedaços a partir do buffer de recepção principal."""
        if not self.receive_buffer:
            return None
        
        chunks = sorted(self.receive_buffer, key=lambda x: x[1])
        
        total_length = chunks[0][0]
        expected_chunks = (total_length + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
        
        if len(chunks) < expected_chunks:
            return None 
        
        data = b''.join(chunk[2] for chunk in chunks)
        
        self.receive_buffer = []
        
        return data[:total_length]
    
    def add_received_chunk(self, total_length, chunk_index, chunk_data):
        """Adiciona um pedaço recebido ao buffer."""
        self.receive_buffer.append((total_length, chunk_index, chunk_data))
        print(f"[Handshake-RX] Recebido pedaço {chunk_index} ({len(chunk_data)} bytes)")


class HandshakeReceiveQueue:
    """
    Fila global para gerenciar operações de recepção de handshake.
    Permite rotear mensagens de handshake para o transporte correto.
    """
    
    def __init__(self):
        self.transports = {}  # mac -> BLEHandshakeTransport
    
    def register_transport(self, mac, transport):
        """Registra um transporte para um MAC específico."""
        self.transports[mac] = transport
    
    def unregister_transport(self, mac):
        """Remove o registro de um transporte."""
        if mac in self.transports:
            del self.transports[mac]
    
    def route_chunk(self, mac, total_length, chunk_index, chunk_data):
        """Roteia um pedaço recebido para o transporte apropriado."""
        if mac in self.transports:
            self.transports[mac].add_received_chunk(total_length, chunk_index, chunk_data)
            return True
        return False
    
    def has_transport(self, mac):
        """Verifica se há transporte registrado para este MAC."""
        return mac in self.transports


# Fila global de recepção
handshake_receive_queue = HandshakeReceiveQueue()
