import sys, os, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from node.router import Router

# Mock simples
class MockBLE:
    def disconnect(self, conn):
        print(f"   [BLE] ✂️  CORTAR CONEXÃO: {conn}")
        # Simula o callback imediato
        if hasattr(self, 'router'): self.router.handle_disconnection(conn)
    def send_packet(self, c, d): pass

def test_failure():
    print("--- Teste de Reação em Cadeia ---")
    ble = MockBLE()
    router = Router(b'\x0A'*16, None, ble)
    ble.router = router

    # 1. Configurar estado saudável
    router.set_uplink("CONN_PAI", hops=1)
    router.downlink_connections.add("CONN_FILHO_1")
    router.downlink_connections.add("CONN_FILHO_2")
    
    print(f"Estado Inicial: Hops={router.hops_to_sink}, Filhos={len(router.downlink_connections)}")

    # 2. Simular Falha do Uplink (Timeout)
    print("\n[!] Simulando queda do Uplink...")
    router.handle_disconnection("CONN_PAI")

    # 3. Validar resultados
    if router.hops_to_sink == -1:
        print("✅ Hops voltaram a -1 (Negativo/Órfão).")
    else:
        print("❌ Hops incorretos.")

    if len(router.downlink_connections) == 0:
        print("✅ Todos os filhos foram desconectados (Cadeia OK).")
    else:
        print("❌ Filhos ainda conectados.")

test_failure()