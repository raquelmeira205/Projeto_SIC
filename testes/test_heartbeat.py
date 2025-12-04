import sys
import os
import time

# Boilerplate para importar as pastas do projeto
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.packet_structs import PacketHeader, MsgType, HeartbeatPayload
from node.router import Router
from sink.heartbeat_service import HeartbeatService

# --- MOCKS (Para simular o que ainda não tens) ---

class MockSecurity:
    def sign_data(self, data): return b'[ASSINATURA_FAKE]'
    def verify_sink_signature(self, data, sig): return sig == b'[ASSINATURA_FAKE]'

class MockBLE:
    def __init__(self, name): 
        self.name = name
        self.last_packet = None # Para validarmos o que foi enviado
    
    def send_packet(self, conn, data):
        self.last_packet = (conn, data)
        print(f"   [{self.name}] -> Enviou UNICAST para '{conn}'")

    def send_to_all_links(self, data):
        self.last_packet = ("BROADCAST", data)
        print(f"   [{self.name}] -> Enviou BROADCAST para vizinhos")

# --- O TESTE ---

def run_focused_test():
    print("=== TESTE FOCADO: HEARTBEAT & FORWARDING ===\n")

    # 1. SETUP
    security = MockSecurity()
    ble_sink = MockBLE("SINK_BLE")
    ble_router = MockBLE("ROUTER_BLE")
    
    # Identificadores
    nid_sink = b'\x01' * 16
    nid_router = b'\x02' * 16
    nid_child = b'\x03' * 16

    # Inicializar Componentes
    sink_service = HeartbeatService(nid_sink, ble_sink, security)
    router = Router(nid_router, security, ble_router)

    # Configurar topologia: Sink <-> Router <-> Child
    router.set_uplink("conn_sink", hops=0) 
    router.downlink_connections.add("conn_child")

    # ==========================================================
    # PARTE 1: TESTAR O SERVIÇO DE HEARTBEAT (SINK)
    # ==========================================================
    print("\n[1] Testando Geração de Heartbeat no Sink...")
    
    # Forçamos o loop do serviço a correr uma vez manualmente
    # (simulamos o que o _heartbeat_loop faria)
    seq = 1
    sig = security.sign_data(seq.to_bytes(4, 'big'))
    payload = HeartbeatPayload.pack(seq, sig)
    packet = PacketHeader.pack(nid_sink, b'\x00'*16, MsgType.HEARTBEAT, payload)
    
    # O Sink envia...
    ble_sink.send_to_all_links(packet)
    
    if ble_sink.last_packet and ble_sink.last_packet[0] == "BROADCAST":
        print("SUCESSO: Sink gerou e enviou heartbeat.")
    else:
        print("FALHA: Sink não enviou nada.")

    # ==========================================================
    # PARTE 2: TESTAR A PROPAGAÇÃO (ROUTER)
    # ==========================================================
    print("\n[2] Testando Propagação (Flooding) no Router...")
    
    # Injetamos o pacote que o Sink "enviou" no Router
    router.process_incoming_packet(packet, "conn_sink")

    # Verificamos se o Router enviou para o filho ("conn_child")
    conn_alvo, dados_env = ble_router.last_packet
    _, _, mtype, _ = PacketHeader.unpack(dados_env)

    if conn_alvo == "conn_child" and mtype == MsgType.HEARTBEAT:
        print("SUCESSO: Router propagou o Heartbeat para o filho.")
    else:
        print(f"FALHA: Router não propagou corretamente. Alvo: {conn_alvo}")

    # ==========================================================
    # PARTE 3: TESTAR FORWARDING E APRENDIZAGEM (ROUTER)
    # ==========================================================
    print("\n[3] Testando Atualização de Tabela (Learning)...")
    
    # Filho envia dados para o Sink
    print("-> Filho envia mensagem...")
    pkt_data = PacketHeader.pack(nid_child, nid_sink, MsgType.DATA, b"Ola")
    
    # Router recebe vindo da conexão "conn_child"
    router.process_incoming_packet(pkt_data, "conn_child")
    
    # 1. Verificar se aprendeu a rota
    if router.forwarding_table.get(nid_child) == "conn_child":
        print("SUCESSO: Tabela atualizada (NID Filho -> conn_child).")
    else:
        print("FALHA: Router não aprendeu a rota.")

    # 2. Verificar se encaminhou para o Sink (Uplink)
    conn_alvo, _ = ble_router.last_packet
    if conn_alvo == "conn_sink":
        print("SUCESSO: Dados encaminhados para o Uplink (Sink).")
    else:
        print("FALHA: Dados não foram para o Uplink.")

if __name__ == "__main__":
    run_focused_test()