import sys
import os
import time


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 

from node.ble_manager import BLEManager 

from common import ble_utils 



if __name__ == "__main__":
    
 
    print("Iniciando o teste de conexão do Node...")
    
   
    node_manager = BLEManager(node_nid="NID_TESTE_A")
    
    
    success = node_manager.find_and_connect_uplink()
    
    if success:
        print("\n[SUCESSO GERAL] Uplink estabelecido. Simulando operação de 5s...")
        time.sleep(5)
        
        # Testar a desconexão
        if node_manager.uplink_addr:
             node_manager.disconnect_from_device(node_manager.uplink_addr)
             node_manager.uplink_addr = None
    else:
        print("\n[FALHA GERAL] Não foi possível estabelecer o uplink.")