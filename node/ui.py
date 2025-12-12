import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

class IoTNodeUI:
    """
    Interface de Utilizador para o dispositivo IoT (Node).
    Exibe status da rede e permite controlo básico.
    """
    def __init__(self, master, node_nid, ble_manager, router):
        self.master = master
        self.node_nid = node_nid
        self.ble_manager = ble_manager
        self.router = router
        
        master.title(f"SIC Node: {node_nid[:4]}...")
        master.geometry("500x600")

        # Configuração básica de estilos
        style = ttk.Style()
        style.configure("TLabel", font=("Arial", 10))
        style.configure("Header.TLabel", font=("Arial", 12, "bold"))

        # --- Título ---
        ttk.Label(master, text="Dispositivo IoT - Rede Ad-hoc", font=("Arial", 14, "bold")).pack(pady=10)
        
        # --- Info Própria ---
        info_frame = ttk.LabelFrame(master, text="Info Local")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"NID: {self.node_nid}").pack(anchor="w", padx=5)
        self.hop_label = ttk.Label(info_frame, text="Hop Count: -1")
        self.hop_label.pack(anchor="w", padx=5)

        # --- Uplink Status ---
        uplink_frame = ttk.LabelFrame(master, text="Uplink")
        uplink_frame.pack(fill="x", padx=10, pady=5)
        
        self.uplink_status_label = ttk.Label(uplink_frame, text="Status: Desconectado", foreground="red")
        self.uplink_status_label.pack(anchor="w", padx=5)
        
        self.uplink_addr_label = ttk.Label(uplink_frame, text="MAC: N/A")
        self.uplink_addr_label.pack(anchor="w", padx=5)

        # --- Downlinks & Routing ---
        routing_frame = ttk.LabelFrame(master, text="Roteamento & Vizinhos")
        routing_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(routing_frame, text="Downlinks Conectados:", style="Header.TLabel").pack(anchor="w", padx=5)
        self.downlinks_text = tk.Text(routing_frame, height=4, width=40)
        self.downlinks_text.pack(padx=5, pady=2)
        
        ttk.Label(routing_frame, text="Tabela de Forwarding:", style="Header.TLabel").pack(anchor="w", padx=5)
        self.forwarding_text = tk.Text(routing_frame, height=6, width=40)
        self.forwarding_text.pack(padx=5, pady=2)

        # --- Controles ---
        controls_frame = ttk.LabelFrame(master, text="Ações de Rede")
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(controls_frame, text="Scan & Connect Uplink", command=self.action_scan).pack(side="left", padx=5, pady=5)
        ttk.Button(controls_frame, text="Disconnect Uplink", command=self.action_disconnect).pack(side="left", padx=5, pady=5)
        ttk.Button(controls_frame, text="Broadcast Test", command=self.action_broadcast).pack(side="left", padx=5, pady=5)

        # Inicia loop de atualização
        self.update_ui()

    def update_ui(self):
        # Update Hop Count
        hc = self.ble_manager.hop_count
        self.hop_label.config(text=f"Hop Count: {hc}")
        
        # Update Uplink
        uplink = self.ble_manager.uplink_addr
        if uplink:
            self.uplink_status_label.config(text="Status: Conectado", foreground="green")
            self.uplink_addr_label.config(text=f"MAC: {uplink}")
        else:
            self.uplink_status_label.config(text="Status: Desconectado", foreground="red")
            self.uplink_addr_label.config(text="MAC: N/A")
            
        # Update Downlinks
        downlinks = list(self.router.downlink_connections) # Set to list
        self.downlinks_text.delete(1.0, tk.END)
        for d in downlinks:
            self.downlinks_text.insert(tk.END, f"{d}\n")
            
        # Update Forwarding Table
        ft = self.router.forwarding_table # Dict {nid: via_mac}
        self.forwarding_text.delete(1.0, tk.END)
        for dest_nid, via_mac in ft.items():
            # Truncate NID for display
            short_nid = dest_nid[:8] + "..." if isinstance(dest_nid, str) else str(dest_nid)[:8]
            self.forwarding_text.insert(tk.END, f"{short_nid} -> {via_mac}\n")

        self.master.after(1000, self.update_ui)

    def action_scan(self):
        def run_scan():
            self.master.title("Scanning...")
            success = self.ble_manager.find_and_connect_uplink()
            if success:
                messagebox.showinfo("Scan", "Uplink conectado!")
            else:
                messagebox.showwarning("Scan", "Nenhum Uplink adequado encontrado.")
            self.master.title(f"SIC Node: {self.node_nid[:4]}...")

        threading.Thread(target=run_scan, daemon=True).start()

    def action_disconnect(self):
        if self.ble_manager.uplink_addr:
            self.ble_manager.trigger_chain_disconnection()
            messagebox.showinfo("Disconnect", "Desconectado do Uplink.")
        else:
            messagebox.showinfo("Disconnect", "Já está desconectado.")

    def action_broadcast(self):
        # Send a dummy packet to all
        msg = b"TEST_BROADCAST"
        count = self.ble_manager.send_to_all_links(msg)
        messagebox.showinfo("Broadcast", f"Enviado para {count} links.")

if __name__ == "__main__":
    # Mock testing
    root = tk.Tk()
    tk.Label(root, text="Execute main.py para usar a UI completa").pack()
    root.mainloop()