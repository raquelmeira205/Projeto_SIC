import sys
import os
import time

# Garantir que o Python encontra os módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 

# Importar o seu Manager
from node.ble_manager import BLEManager 
# Importar a função real de scanning (vai ser chamada pelo Manager)
from common import ble_utils 

NODE_NID = "NODE_TESTE_A"

if __name__ == "__main__":
    
    # 1. Verificação de Pré-requisitos (Opcional, mas útil)
    print("--- Verificação de Estado do BlueZ ---")
    try:
        # Tenta obter o objeto do adaptador para ver se o BlueZ está OK
        adapter = ble_utils.BUS.get("org.bluez", ble_utils.ADAPTER_PATH)
        print("[+] Adaptador BlueZ acessível.")
    except Exception as e:
        print(f"[!] ERRO CRÍTICO: Não foi possível aceder ao BlueZ/D-Bus: {e}")
        print("    Certifique-se que o serviço 'bluetooth' está ativo ('sudo systemctl start bluetooth') e o adaptador ligado ('sudo bluetoothctl -> power on').")
        sys.exit(1)


    # 2. Inicializar e Testar o Uplink
    print(f"\n--- Iniciando o Node {NODE_NID} ---")
    node_manager = BLEManager(node_nid=NODE_NID)
    
    print("\n[*] Tentando encontrar e conectar o melhor Uplink (Hops + RSSI)...")
    
    success = node_manager.find_and_connect_uplink()
    
    if success:
        print("\n[SUCESSO GERAL] Uplink estabelecido.")
        print(f"    Conectado a: {node_manager.uplink_addr}")
        print(f"    Meu Hop Count: {node_manager.hop_count}")
        
        # Simular operação de rede (30s)
        print("\n[*] Simulação de Operação (30s)...")
        time.sleep(30)
        
        # Testar a desconexão
        if node_manager.uplink_addr:
            node_manager.disconnect_from_device(node_manager.uplink_addr)
            node_manager.uplink_addr = None
    else:
        print("\n[FALHA GERAL] Não foi possível estabelecer o uplink.")
        
    print("\n--- Teste de Hardware Concluído ---")