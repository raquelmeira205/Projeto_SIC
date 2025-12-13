import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import time

class IoTNodeUI:
    def __init__(self, master, node_ref=None):
        self.master = master
        self.node = node_ref
        master.title("SIC IoT Node UI")
        master.geometry("600x700")

        # Configuração de Estilo
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))

        # --- Frames ---
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Info Frame
        self.create_info_frame()
        
        # 2. Network Tables Frame
        self.create_tables_frame()
        
        # 3. Stats Frame
        self.create_stats_frame()

        # 4. Controls Frame
        self.create_controls_frame()

        # Loop de atualização
        self.update_ui()

    def create_info_frame(self):
        frame = ttk.LabelFrame(self.main_frame, text="Device Information", padding="5")
        frame.pack(fill=tk.X, pady=5)
        
        grid_opts = {'padx': 5, 'pady': 2, 'sticky': 'w'}

        # Device NID
        ttk.Label(frame, text="My NID:", style="Header.TLabel").grid(row=0, column=0, **grid_opts)
        self.lbl_nid = ttk.Label(frame, text="Loading...")
        self.lbl_nid.grid(row=0, column=1, **grid_opts)

        # Uplink Status
        ttk.Label(frame, text="Uplink Status:", style="Header.TLabel").grid(row=1, column=0, **grid_opts)
        self.lbl_uplink_status = ttk.Label(frame, text="Disconnected", foreground="red")
        self.lbl_uplink_status.grid(row=1, column=1, **grid_opts)

        # Uplink NID
        ttk.Label(frame, text="Uplink NID:", style="Header.TLabel").grid(row=2, column=0, **grid_opts)
        self.lbl_uplink_nid = ttk.Label(frame, text="N/A")
        self.lbl_uplink_nid.grid(row=2, column=1, **grid_opts)
        
        # Sink NID
        ttk.Label(frame, text="Sink NID:", style="Header.TLabel").grid(row=3, column=0, **grid_opts)
        self.lbl_sink_nid = ttk.Label(frame, text="Unknown")
        self.lbl_sink_nid.grid(row=3, column=1, **grid_opts)

    def create_tables_frame(self):
        frame = ttk.LabelFrame(self.main_frame, text="Network Tables", padding="5")
        frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Downlinks
        ttk.Label(frame, text="Downlinks (Start of Chain):").pack(anchor='w')
        self.lst_downlinks = tk.Listbox(frame, height=4)
        self.lst_downlinks.pack(fill=tk.X, padx=5, pady=2)
        
        # Forwarding Table
        ttk.Label(frame, text="Forwarding Table (NID -> Next Hop):").pack(anchor='w')
        self.lst_forwarding = tk.Listbox(frame, height=6)
        self.lst_forwarding.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

    def create_stats_frame(self):
        frame = ttk.LabelFrame(self.main_frame, text="Statistics", padding="5")
        frame.pack(fill=tk.X, pady=5)
        
        self.lbl_stats_heartbeat = ttk.Label(frame, text="Lost Heartbeats: 0")
        self.lbl_stats_heartbeat.pack(anchor='w', padx=5)
        
        self.lbl_stats_routed = ttk.Label(frame, text="Routed Messages: 0")
        self.lbl_stats_routed.pack(anchor='w', padx=5)

    def create_controls_frame(self):
        frame = ttk.LabelFrame(self.main_frame, text="Controls & Messages", padding="5")
        frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Send to Sink
        send_frame = ttk.Frame(frame)
        send_frame.pack(fill=tk.X, pady=2)
        
        self.entry_msg = ttk.Entry(send_frame)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        btn_send = ttk.Button(send_frame, text="Send to Sink", command=self.send_message)
        btn_send.pack(side=tk.RIGHT, padx=5)

        # Received Messages
        ttk.Label(frame, text="Received Messages:").pack(anchor='w', pady=2)
        self.lst_messages = tk.Listbox(frame, height=6)
        self.lst_messages.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        # Menu
        menubar = tk.Menu(self.master)
        net_menu = tk.Menu(menubar, tearoff=0)
        net_menu.add_command(label="Reset Stats", command=self.reset_stats)
        menubar.add_cascade(label="Network Controls", menu=net_menu)
        self.master.config(menu=menubar)

    def update_ui(self):
        if not self.node:
            self.master.after(1000, self.update_ui)
            return

        # 1. Info
        self.lbl_nid.config(text=self.node.node_nid.hex())
        
        uplink = self.node.ble_manager.uplink_addr
        if uplink:
            self.lbl_uplink_status.config(text=f"Connected ({uplink})", foreground="green")
        else:
            self.lbl_uplink_status.config(text="Disconnected", foreground="red")
            
        up_nid = self.node.ble_manager.uplink_nid
        self.lbl_uplink_nid.config(text=up_nid.hex() if up_nid else "N/A")
        
        sink = self.node.router.sink_nid
        self.lbl_sink_nid.config(text=sink.hex() if sink else "Unknown")

        # 2. Tables
        # Downlinks (Need to pull from router or manager)
        # Using forwarding table to infer NIDs reachable
        down_conns = self.node.router.downlink_connections
        self.lst_downlinks.delete(0, tk.END)
        if hasattr(self.node.ble_manager, 'downlinks'): # If ble_manager tracks them
            for mac in self.node.ble_manager.downlinks:
                 self.lst_downlinks.insert(tk.END, mac)
        elif down_conns:
             for conn in down_conns:
                 self.lst_downlinks.insert(tk.END, conn)
        else:
             self.lst_downlinks.insert(tk.END, "No direct downlinks")
             
        # Forwarding
        self.lst_forwarding.delete(0, tk.END)
        for dest, hop in self.node.router.forwarding_table.items():
            self.lst_forwarding.insert(tk.END, f"{dest.hex()} -> {hop}")

        # 3. Stats
        stats = self.node.router.stats
        self.lbl_stats_heartbeat.config(text=f"Lost Heartbeats: {stats['lost_heartbeats']}")
        self.lbl_stats_routed.config(text=f"Routed Messages: {stats['routed_messages']}")

        # 4. Messages
        # Only add new messages (naive implementation: clear and re-add for simplicity or check length)
        # Current listbox size
        current_count = self.lst_messages.size()
        msgs = stats['received_messages']
        if len(msgs) > current_count:
            # Add only new ones
            for i in range(current_count, len(msgs)):
                sender, txt = msgs[i]
                self.lst_messages.insert(tk.END, f"[{sender}]: {txt}")
                self.lst_messages.see(tk.END)

        self.master.after(1000, self.update_ui)

    def send_message(self):
        text = self.entry_msg.get()
        if not text: return
        
        if self.node.send_to_sink(text):
            self.entry_msg.delete(0, tk.END)
            # Optional: log sent message
            # self.lst_messages.insert(tk.END, f"[Me -> Sink]: {text}")
        else:
            messagebox.showerror("Error", "Failed to send. Check connection/sink NID.")

    def reset_stats(self):
        if self.node:
            self.node.router.stats["lost_heartbeats"] = 0
            self.node.router.stats["routed_messages"] = 0
            # self.node.router.stats["received_messages"] = [] # Optional
            self.update_ui()