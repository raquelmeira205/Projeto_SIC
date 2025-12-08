import sys
import os
import time

# Garantir que o Python encontra os módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 

# Importar o Manager
from node.ble_manager import BLEManager 
# Importar a função real de scanning
from common import ble_utils 

NODE_NID = "NODE_TESTE_A"

if __name__ == "__main__":
    
    # 1. Verificação de Pré-requisitos
    print("--- Verificação de Estado do BlueZ ---")
    try:
        # Tenta obter o objeto do adaptador para ver se o BlueZ está OK
        adapter = ble_utils.BUS.get("org.bluez", ble_utils.ADAPTER_PATH)
        print("[+] Adaptador BlueZ acessível.")
    except Exception as e:
        print(f"[!] ERRO CRÍTICO: Não foi possível aceder ao BlueZ/D-Bus: {e}")
        print("    Certifique-se que o serviço 'bluetooth' está ativo e o adaptador ligado.")
        sys.exit(1)


    # 2. Inicializar o Node
    print(f"\n--- Iniciando o Node {NODE_NID} ---")
    node_manager = BLEManager(node_nid=NODE_NID)
    
    print("\n[*] Tentando encontrar e conectar o melhor Uplink (Hops + RSSI)...")
    
    # NOTA: Se estiveres a usar um Dongle que não emite 'hop_count', 
    # certifica-te que alteraste temporariamente o 'ble_manager.py' para aceitar qualquer nó.
    success = node_manager.find_and_connect_uplink()
    
    if success:
        print("\n[SUCESSO GERAL] Uplink estabelecido.")
        print(f"    Conectado a: {node_manager.uplink_addr}")
        print(f"    Meu Hop Count: {node_manager.hop_count}")
        
        # ---------------------------------------------------------
        # PREPARAÇÃO PARA O TESTE DE DESCONEXÃO EM CADEIA
        # ---------------------------------------------------------
        
        # 3. Injetar um Downlink Falso
        # Isto serve para verificarmos se a função 'trigger_chain_disconnection' 
        # realmente apaga os filhos quando o pai morre.
        fake_downlink_mac = "00:00:00:00:00:00" # MAC Fictício
        node_manager.downlinks[fake_downlink_mac] = "Objeto_DBus_Fake"
        
        print(f"\n[*] Downlink Falso injetado: {fake_downlink_mac}")
        print(f"    Estado Atual: Uplink={node_manager.uplink_addr} | Downlinks={list(node_manager.downlinks.keys())}")

        # 4. Loop de Monitorização (O Teste Real)
        print("\n" + "="*60)
        print(" INSTRUÇÃO PARA O UTILIZADOR:")
        print(" 1. O sistema está agora a monitorizar a conexão.")
        print(" 2. POR FAVOR, REMOVA O DONGLE (UPLINK) FISICAMENTE AGORA.")
        print(" 3. Aguarde (5 a 10s) e veja se o script reage automaticamente.")
        print("="*60 + "\n")

        try:
            while True:
                # Chama a função de vigilância (que implementaste no ble_manager)
                # Esta função deteta se o 'device.Connected' mudou para False
                node_manager.monitor_connection_status()

                # VERIFICAÇÃO DE SUCESSO
                # Se o uplink_addr passou a None, significa que o Manager reagiu!
                if node_manager.uplink_addr is None:
                    print("\n\n[!!!] REAÇÃO DETETADA PELO GESTOR!")
                    print("[*] O Uplink foi removido da configuração.")
                    
                    # Teste da 'Cadeia': A lista de downlinks deve estar vazia
                    if len(node_manager.downlinks) == 0:
                        print("[PASSOU] SUCESSO: A lista de Downlinks foi limpa (Cadeia quebrada).")
                    else:
                        print(f"[FALHOU] ERRO: Os downlinks ainda persistem: {node_manager.downlinks}")

                    # Teste do Estado: Hop count deve ser -1
                    if node_manager.hop_count == -1:
                        print("[PASSOU] SUCESSO: Hop Count resetado para -1.")
                    else:
                        print(f"[FALHOU] Hop Count incorreto: {node_manager.hop_count}")
                    
                    print("\n[INFO] O sistema deve estar agora a tentar fazer Scan novamente...")
                    print("--- Teste de Lógica Concluído com Sucesso ---")
                    break
                
                # Feedback visual de que o loop está a correr
                print(".", end="", flush=True)
                time.sleep(1) # Verifica a cada segundo

        except KeyboardInterrupt:
            print("\n\nTeste interrompido pelo utilizador.")

    else:
        print("\n[FALHA GERAL] Não foi possível estabelecer o uplink inicial para começar o teste.")
        print("Sugestão: Verifique se alterou o filtro de 'hop_count' no ble_manager se estiver a usar um dongle genérico.")
        
    print("\n--- Fim do Script ---")