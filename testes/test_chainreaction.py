import sys
from unittest.mock import MagicMock
import time
import os

# --- TRUQUE 1: Mockar dependências de sistema (pydbus, etc) ---
sys.modules["pydbus"] = MagicMock()
sys.modules["gi.repository"] = MagicMock()
# -------------------------------------------------------------

# Ajustar path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from node.router import Router, TIMEOUT_LIMIT

# Classes Falsas
class MockSecurity:
    def verify_sink_signature(self, d, s): return True
    def sign_data(self, d): return b'sig'

class MockBLEManager:
    def __init__(self, nid):
        self.router_ref = None
        self.connections = set()
        # Adicionar atributos que o Router espera ler
        self.uplink_addr = None
        self.uplink_nid = None
        self.hop_count = -1

    def disconnect_from_device(self, mac):
        print(f"   [BLE] ✂️  CORTAR CONEXÃO FÍSICA: {mac}")
        if mac in self.connections:
            self.connections.remove(mac)
            if self.router_ref:
                self.router_ref.handle_disconnection(mac)
    
    def update_advertisement(self):
        pass

def test_chain_reaction():
    print("\n=========================================================")
    print("   TESTE DE REAÇÃO EM CADEIA (HEARTBEAT TIMEOUT)")
    print("=========================================================\n")
    
    # 1. Setup
    ble = MockBLEManager(b'\x0A'*16)
    router = Router(b'\x0A'*16, MockSecurity(), ble)
    ble.router_ref = router

    # --- CORREÇÃO DO ERRO AQUI ---------------------------------------
    # O Router quer fazer handshake, mas não temos certificados no teste.
    # Vamos substituir a função perform_handshake por um Mock que retorna
    # uma chave falsa imediatamente.
    router.perform_handshake = MagicMock(return_value=b'\xAA'*32)
    # -----------------------------------------------------------------

    # 2. Criar a Rede (Topologia)
    uplink = "AA:AA:AA:AA:AA:AA"
    filho1 = "BB:BB:BB:BB:BB:BB"
    filho2 = "CC:CC:CC:CC:CC:CC"

    # Simular conexões BLE ativas
    ble.connections.add(uplink)
    ble.connections.add(filho1)
    ble.connections.add(filho2)

    # Configurar o Router
    print("[1] Configurando: Uplink + 2 Filhos")
    
    # Agora isto vai funcionar porque o handshake é "falso"
    router.set_uplink(uplink, hops=1)
    
    # Adicionar filhos manualmente e criar chaves de sessão falsas para eles
    # (Necessário porque o router agora verifica chaves antes de enviar disconnects autenticados)
    router.downlink_connections.add(filho1)
    router.link_keys[filho1] = b'\xBB'*32
    router.my_counters[filho1] = 0
    
    router.downlink_connections.add(filho2)
    router.link_keys[filho2] = b'\xCC'*32
    router.my_counters[filho2] = 0

    print(f"   Estado Inicial: Uplink={uplink} | Filhos={router.downlink_connections}")

    # 3. O Teste: Simular Timeout
    print("\n[2] Simulando paragem do Heartbeat (Timeout)...")
    # Batota: Recuar o relógio para forçar timeout imediato (16 segundos atrás)
    router.last_heartbeat_time = time.time() - (TIMEOUT_LIMIT + 1)
    
    print("   Aguardando watchdog detetar o timeout (2s)...")
    time.sleep(2.1)

    # 4. Verificações
    print("\n--- RESULTADOS ---")
    
    # Ver se o Uplink morreu
    if router.uplink_connection is None:
        print("✅ SUCESSO: Uplink removido do Router.")
    else:
        print(f"❌ FALHA: Router ainda tem uplink: {router.uplink_connection}")

    # Ver se os filhos foram cortados
    if len(router.downlink_connections) == 0:
        print("✅ SUCESSO: Lista de filhos limpa (Reação em Cadeia).")
    else:
        print(f"❌ FALHA: Filhos ainda na lista: {router.downlink_connections}")

    # Ver se o BLE recebeu ordem de corte
    # Nota: O MockBLE remove da lista 'connections' quando recebe o comando disconnect
    if len(ble.connections) == 0:
        print("✅ SUCESSO TOTAL: Todos os dispositivos foram desconectados fisicamente.")
    else:
        print(f"❌ FALHA: O BLE ainda tem conexões ativas: {ble.connections}")

    router._stop_monitor = True

if __name__ == "__main__":
    test_chain_reaction()