import time
import threading
from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload

class HeartbeatService:
    """
    Serviço que gera e transmite Heartbeats periodicamente a partir do Sink.
    Os heartbeats são assinados para garantir autenticidade.
    """
    
    def __init__(self, sink_nid, connection_manager, security_module):
        """
        Inicializa o serviço de Heartbeat.
        
        :param sink_nid: NID do Sink.
        :param connection_manager: Gerenciador de conexões para envio.
        :param security_module: Módulo para assinar os heartbeats.
        """
        self.sink_nid = sink_nid
        self.conn_manager = connection_manager 
        self.security = security_module        
        self.running = False
        self.sequence_number = 0

    def start(self):
        """Inicia a thread de geração de heartbeats."""
        self.running = True
        thread = threading.Thread(target=self._heartbeat_loop)
        thread.daemon = True 
        thread.start()

    def _heartbeat_loop(self):
        """Loop principal que envia heartbeats a cada intervalo."""
        print("[Sink] Serviço de Heartbeat iniciado.")
        
        time.sleep(2)

        while self.running:
            try:
                data_to_sign = self.sequence_number.to_bytes(4, 'big')
                
                signature = self.security.sign_data(data_to_sign)
                
                hb_payload = HeartbeatPayload.pack(self.sequence_number, signature)
                
                if not isinstance(hb_payload, bytes):
                    hb_payload = bytes(hb_payload)

                # print(f"[Sink] A enviar Heartbeat #{self.sequence_number}")
                
                if hasattr(self.conn_manager, 'session_keys'):
                    connected_macs = list(self.conn_manager.session_keys.keys())
                    
                    for mac in connected_macs:
                        try:
                            self.conn_manager.send_authenticated_packet(
                                mac, 
                                self.sink_nid, 
                                b'\x00'*16,
                                MsgType.HEARTBEAT, 
                                hb_payload
                            )
                        except Exception as e:
                            print(f"[Sink] Falha ao enviar Heartbeat para {mac}: {e}")

                self.sequence_number += 1
                
            except Exception as e:
                print(f"[Sink] Erro crítico no loop de Heartbeat: {e}")
            
            time.sleep(10)

    def stop(self):
        """Para o serviço de Heartbeat."""
        self.running = False