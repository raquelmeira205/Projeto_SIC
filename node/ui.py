import tkinter as tk
from tkinter import ttk
import random
import time

# --- MOCKUP DE DADOS (Substituir por dados reais do seu Node) ---
# Em um sistema real, o NID seria lido de um ficheiro de certificado/configuração.
# O projeto requer um NID de 128 bits, aqui simulado como um hex string.
MOCK_DEVICE_NID = "1A2B3C4D5E6F7890ABCDEF0123456789"

# Em um sistema real, estas variáveis seriam atualizadas pelo módulo de roteamento
# (node/router) quando o uplink se estabelece ou falha.
mock_uplink_status = "Desconectado (Procurando Uplink...)"
mock_uplink_nid = "N/A"

# Mockup para a cor de status
STATUS_COLOR_DISCONNECTED = "red"
STATUS_COLOR_CONNECTED = "green"
mock_status_color = STATUS_COLOR_DISCONNECTED
# -----------------------------------------------------------------

class IoTNodeUI:
    """
    Boilerplate da Interface de Utilizador para o dispositivo IoT (Node).
    Exibe o NID do dispositivo e o status do Uplink.
    """
    def __init__(self, master, node_ref=None):
        self.master = master
        self.node_ref = node_ref
        master.title("SIC IoT Node UI")

        # Configuração básica de estilos
        style = ttk.Style()
        style.configure("TLabel", font=("Arial", 10))

        # --- Título ---
        self.title_label = ttk.Label(master, text="Dispositivo IoT - Rede Ad-hoc", font=("Arial", 14, "bold"))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)

        # --- NID do Dispositivo ---
        nid_text = self.node_ref.node_nid.hex() if self.node_ref else MOCK_DEVICE_NID
        ttk.Label(master, text="NID do Dispositivo:", font=("Arial", 10, "bold")).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.nid_label = ttk.Label(master, text=nid_text)
        self.nid_label.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # --- Status do Uplink ---
        ttk.Label(master, text="Status do Uplink:", font=("Arial", 10, "bold")).grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.status_label = ttk.Label(master, text=mock_uplink_status, foreground=mock_status_color)
        self.status_label.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # --- NID do Uplink ---
        ttk.Label(master, text="NID do Uplink:", font=("Arial", 10, "bold")).grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.uplink_nid_label = ttk.Label(master, text=mock_uplink_nid)
        self.uplink_nid_label.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        # Inicia a função de atualização de 1 em 1 segundo (simulação)
        self.update_ui()

    def update_ui(self):
        """
        Função chamada periodicamente para atualizar o estado da UI.
        """
        if self.node_ref:
            # Ler dados reais
            uplink = self.node_ref.ble_manager.uplink_addr
            if uplink:
                status_text = "Conectado"
                status_color = "green"
                uplink_text = uplink # Deveria ser NID, mas usamos MAC por enquanto
            else:
                status_text = "Desconectado"
                status_color = "red"
                uplink_text = "N/A"
        else:
            # Mockup
            status_text = mock_uplink_status
            status_color = mock_status_color
            uplink_text = mock_uplink_nid

        self.status_label.config(text=status_text, foreground=status_color)
        self.uplink_nid_label.config(text=uplink_text)
        
        # Agenda a próxima atualização (1000ms = 1 segundo)
        self.master.after(1000, self.update_ui)

# --- SIMULAÇÃO DE MUDANÇA DE ESTADO (PARA DEMONSTRAÇÃO) ---
# Esta função simula o que aconteceria se a rede encontrasse um uplink.
def simulate_network_change():
    """Simula a conexão a um uplink após 5 segundos."""
    global mock_uplink_status, mock_uplink_nid, mock_status_color
    
    time.sleep(5) # Espera 5 segundos
    
    # Simula a conexão bem-sucedida
    new_uplink_nid = "2F4E6D8B0A1C3E579F2D4B6A8C0E1F35"
    print(f"\n[SIMULAÇÃO] Uplink encontrado: {new_uplink_nid}")
    
    mock_uplink_status = "Conectado"
    mock_uplink_nid = new_uplink_nid
    mock_status_color = STATUS_COLOR_CONNECTED

# --- EXECUÇÃO ---
if __name__ == "__main__":
    # Inicia a thread de simulação em segundo plano
    import threading
    threading.Thread(target=simulate_network_change, daemon=True).start()
    
    # Inicia a interface gráfica
    root = tk.Tk()
    app = IoTNodeUI(root)
    root.mainloop()