import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload

class HeartbeatService:
    def __init__(self, sink_nid, connection_manager, security_module):
        self.sink_nid = sink_nid
        self.conn_manager = connection_manager 
        self.security = security_module        
        self.running = False
        self.sequence_number = 0

    def start(self):
        self.running = True
        thread = threading.Thread(target=self._heartbeat_loop)
        thread.daemon = True 
        thread.start()

    def _heartbeat_loop(self):
        print("[Sink] Serviço de Heartbeat iniciado.")
        
        # Pequeno delay inicial para garantir que tudo arrancou
        time.sleep(2)

        while self.running:
            try:
                # 1. Preparar os dados a assinar (Sequence Number)
                data_to_sign = self.sequence_number.to_bytes(4, 'big')
                
                # 2. Assinar com a chave privada do Sink
                signature = self.security.sign_data(data_to_sign)
                
                # 3. Empacotar o Payload do Heartbeat (Seq + Assinatura)
                hb_payload = HeartbeatPayload.pack(self.sequence_number, signature)
                
                # Garantia de segurança: Converter explicitamente para bytes
                if not isinstance(hb_payload, bytes):
                    hb_payload = bytes(hb_payload)

                print(f"[Sink] A enviar Heartbeat #{self.sequence_number} (Payload: {len(hb_payload)} bytes)")
                
                # 4. Enviar para todos os nós autenticados
                if hasattr(self.conn_manager, 'session_keys'):
                    # Usar list() cria uma cópia segura das chaves para iterar
                    connected_macs = list(self.conn_manager.session_keys.keys())
                    
                    if not connected_macs:
                        # print("[Sink] Sem nós conectados para enviar Heartbeat.")
                        pass

                    for mac in connected_macs:
                        try:
                            # A função send_authenticated_packet já trata do cabeçalho e MAC do pacote
                            self.conn_manager.send_authenticated_packet(
                                mac, 
                                self.sink_nid, 
                                b'\x00'*16, # Broadcast NID
                                MsgType.HEARTBEAT, 
                                hb_payload
                            )
                        except Exception as e:
                            print(f"[Sink] Falha ao enviar Heartbeat para {mac}: {e}")

                self.sequence_number += 1
                
            except Exception as e:
                print(f"[Sink] Erro crítico no loop de Heartbeat: {e}")
            
            # Esperar pelo próximo ciclo
            time.sleep(10) # Aumentei para 10s para reduzir spam no log enquanto debugas

    def stop(self):
        self.running = False