import threading
import time
import sys

class NodeCLI:
    """
    Interface de Linha de Comando (CLI) para interação com o Nó IoT.
    Gerencia a entrada do usuário e exibe status e estatísticas do nó.
    """

    def __init__(self, node_ref):
        """
        Inicializa a CLI.

        :param node_ref: Referência para o objeto Node principal.
        """
        self.node = node_ref
        self.running = True
        self.scan_results = []
        self.last_status_time = 0
        
    def start(self):
        """
        Inicia a interface de linha de comando.
        Exibe o cabeçalho e inicia a thread de monitoramento e o loop de comandos.
        """
        print("\n" + "="*60)
        print("SIC IoT Node - Command Line Interface")
        print("="*60)
        print(f"Node NID: {self.node.node_nid.hex()}")
        print("\nType 'help' for available commands\n")
        
        status_thread = threading.Thread(target=self._status_monitor, daemon=True)
        status_thread.start()
        
        self._command_loop()
    
    def _status_monitor(self):
        """
        Thread em background para monitorar e exibir o status periodicamente.
        """
        while self.running:
            time.sleep(30)
            if self.running:
                self._print_status_line()
    
    def _print_status_line(self):
        """
        Imprime uma linha de status atualizada com informações resumidas do nó.
        """
        uplink = self.node.ble_manager.uplink_addr
        hop = self.node.ble_manager.hop_count
        downlinks = len(self.node.router.downlink_connections)
        lost_hb = self.node.router.stats['lost_heartbeats']
        routed = self.node.router.stats['routed_messages']
        
        if uplink:
            status = f"UP:{uplink[:8]}... Hop:{hop} DL:{downlinks} LostHB:{lost_hb} Routed:{routed}"
        else:
            status = f"Disconnected | LostHB:{lost_hb} Routed:{routed}"
        
        print(f"\n[STATUS] {status}")
        print("> ", end="", flush=True)
    
    def _command_loop(self):
        """
        Loop principal de processamento de comandos do usuário.
        """
        while self.running:
            try:
                cmd = input("> ").strip().lower()
                
                if not cmd:
                    continue
                
                parts = cmd.split(maxsplit=1)
                command = parts[0]
                args = parts[1] if len(parts) > 1 else ""
                
                if command == "help":
                    self._cmd_help()
                elif command == "scan":
                    self._cmd_scan()
                elif command == "connect":
                    self._cmd_connect(args)
                elif command == "status":
                    self._cmd_status()
                elif command == "stats":
                    self._cmd_stats()
                elif command == "netctrl":  
                    self._cmd_network_control()
                elif command == "send":
                    self._cmd_send(args)
                elif command == "quit" or command == "exit":
                    self._cmd_quit()
                    break
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except EOFError:
                self._cmd_quit()
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _cmd_help(self):
        """
        Exibe a lista de comandos disponíveis.
        """
        print("\nAvailable Commands:")
        print("  scan              - Scan for nearby BLE devices")
        print("  connect <index>   - Connect to device by index from scan results")
        print("  connect <MAC>     - Connect to device by MAC address (XX:XX:XX:XX:XX:XX)")
        print("  status            - Show current node status")
        print("  stats             - Show statistics")
        print("  netctrl           - Network Control (Simulate Failures)")
        print("  send <message>    - Send message to sink")
        print("  help              - Show this help message")
        print("  quit              - Exit application")
        print()
    
    def _cmd_scan(self):
        """
        Comando para iniciar a varredura BLE e exibir os resultados.
        """
        print("Scanning for devices...")
        
        def scan_thread():
            try:
                results = self.node.scan_for_uplinks()
                self.scan_results = results
                
                print(f"\nFound {len(results)} devices:")
                print("-" * 70)
                for idx, dev in enumerate(results):
                    name = dev.get('name', dev.get('mac'))
                    hop = dev.get('hop_count', -1)
                    rssi = dev.get('rssi', 0)
                    mac = dev.get('mac', 'Unknown')
                    print(f"  [{idx}] {name:20s} | Hop: {hop:2d} | RSSI: {rssi:3d} | {mac}")
                print("-" * 70)
                print(f"Use 'connect <index>' to connect to a device\n")
                print("> ", end="", flush=True)
            except Exception as e:
                print(f"Scan error: {e}")
                print("> ", end="", flush=True)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def _cmd_connect(self, args):
        """
        Comando para conectar a um dispositivo, seja por índice ou endereço MAC.
        
        :param args: Argumentos do comando (índice ou MAC).
        """
        if not args:
            print("Usage: connect <index|MAC>")
            return
        
        if ':' in args:
            mac = args.strip()
            name = mac
            print(f"Connecting to {mac}...")
            
            def connect_thread():
                try:
                    success = self.node.force_connect(mac)
                    if success:
                        print(f"\n✓ Connected to {name}")
                    else:
                        print(f"\n✗ Failed to connect to {name}")
                    print("> ", end="", flush=True)
                except Exception as e:
                    print(f"\n✗ Connection error: {e}")
                    print("> ", end="", flush=True)
            
            threading.Thread(target=connect_thread, daemon=True).start()
            return
        
        try:
            index = int(args)
        except ValueError:
            print("Invalid input. Must be an index number or MAC address (XX:XX:XX:XX:XX:XX)")
            return
        
        if index < 0 or index >= len(self.scan_results):
            print(f"Invalid index. Must be between 0 and {len(self.scan_results)-1}")
            return
        
        device = self.scan_results[index]
        mac = device['mac']
        name = device.get('name', mac)
        
        print(f"Connecting to {name} ({mac})...")
        
        def connect_thread():
            try:
                success = self.node.force_connect(mac)
                if success:
                    print(f"\n✓ Connected to {name}")
                else:
                    print(f"\n✗ Failed to connect to {name}")
                print("> ", end="", flush=True)
            except Exception as e:
                print(f"\n✗ Connection error: {e}")
                print("> ", end="", flush=True)
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def _cmd_status(self):
        """
        Exibe o status atual do nó, incluindo informações de uplink, downlinks e estatísticas.
        """
        print("\n" + "="*60)
        print("NODE STATUS")
        print("="*60)
        
        print(f"Node NID:     {self.node.node_nid.hex()}")
        
        uplink = self.node.ble_manager.uplink_addr
        uplink_nid = self.node.ble_manager.uplink_nid
        hop = self.node.ble_manager.hop_count
        
        if uplink:
            print(f"Uplink:       {uplink} (Connected)")
            print(f"Uplink NID:   {uplink_nid.hex() if uplink_nid else 'Unknown'}")
            print(f"Hop Count:    {hop}")
        else:
            print(f"Uplink:       Disconnected")
            print(f"Hop Count:    {hop}")
        
        downlink_connections = self.node.router.downlink_connections
        print(f"\nDownlinks:    {len(downlink_connections)} connection(s)")
        if downlink_connections:
            for conn_mac in downlink_connections:
                nid = "Unknown"
                for dest_nid, next_hop in self.node.router.forwarding_table.items():
                    if next_hop == conn_mac:
                        nid = dest_nid.hex()
                        break
                print(f"  - {conn_mac} (NID: {nid})")
        
        sink_nid = self.node.router.sink_nid
        print(f"\nSink NID:     {sink_nid.hex() if sink_nid else 'Unknown'}")
        
        stats = self.node.router.stats
        print(f"\n--- Statistics ---")
        print(f"Lost Heartbeats:  {stats['lost_heartbeats']}")
        print(f"Routed Messages:  {stats['routed_messages']}")
        print(f"Received Messages: {len(stats.get('received_messages', []))}")
        
        print(f"\n--- Forwarding Table ---")
        print(f"Total Entries: {len(self.node.router.forwarding_table)}")
        for dest, next_hop in list(self.node.router.forwarding_table.items())[:5]:
            print(f"  {dest.hex()} -> {next_hop}")
        
        if len(self.node.router.forwarding_table) > 5:
            print(f"  ... and {len(self.node.router.forwarding_table) - 5} more")
        
        print("="*60 + "\n")
    
    def _cmd_stats(self):
        """
        Exibe estatísticas detalhadas da rede e do nó.
        """
        stats = self.node.router.stats
        
        print("\n" + "="*60)
        print("STATISTICS")
        print("="*60)
        
        print("--- Network Health ---")
        print(f"Lost Heartbeats:  {stats['lost_heartbeats']}")
        uplink = self.node.ble_manager.uplink_addr
        if uplink:
            print(f"Uplink Status:    Connected to {uplink}")
        else:
            print(f"Uplink Status:    Disconnected")
        
        print(f"\n--- Message Statistics ---")
        print(f"Routed Messages:  {stats['routed_messages']}")
        print(f"Received Messages: {len(stats.get('received_messages', []))}")
        
        downlink_count = len(self.node.router.downlink_connections)
        print(f"\n--- Network Topology ---")
        print(f"Hop Count:        {self.node.ble_manager.hop_count}")
        print(f"Downlinks:        {downlink_count}")
        print(f"Forwarding Table: {len(self.node.router.forwarding_table)} entries")
        
        messages = stats.get('received_messages', [])
        if messages:
            print("\n--- Recent Messages ---")
            for sender, msg in messages[-5:]:
                sender_short = sender[:16] + "..." if len(sender) > 16 else sender
                msg_preview = msg[:40] + "..." if len(msg) > 40 else msg
                print(f"  [{sender_short}]: {msg_preview}")
        else:
            print("\n--- Recent Messages ---")
            print("  No messages received yet")
        
        print("="*60 + "\n")
        
    def _cmd_network_control(self):
        """
        Menu para controle de rede (simulação de falhas).
        Permite bloquear heartbeats de downlinks específicos.
        """
        print("\n" + "="*60)
        print("NETWORK CONTROL - FAILURE SIMULATION")
        print("="*60)
        
        if not hasattr(self.node.router, 'get_downlinks_status'):
            print("Error: Router does not support network control features.")
            print("Please update node/router.py first.")
            return

        children = self.node.router.get_downlinks_status()
        
        if not children:
            print("[!] No downlinks connected. Cannot simulate failure.")
            return

        print("Select a downlink to BLOCK/UNBLOCK heartbeats:")
        print("Blocking heartbeats simulates a broken link to that device.")
        print("-" * 60)
        
        for i, (mac, is_blocked) in enumerate(children):
            state = "[BLOCKED ❌]" if is_blocked else "[ACTIVE ✅]"
            print(f"  {i}) {mac} {state}")
        print("-" * 60)

        try:
            sel = input("\nEnter index to toggle (or Enter to cancel): ")
            if sel.strip() == "": return
            
            idx = int(sel)
            if 0 <= idx < len(children):
                target_mac = children[idx][0]
                blocked = self.node.router.toggle_heartbeat_block(target_mac)
                
                if blocked:
                    print(f"\n[!!!] Heartbeats BLOCKED for {target_mac}.")
                    print("      The child node should detect timeout in ~15s.")
                else:
                    print(f"\n[OK] Heartbeats RESTORED for {target_mac}.")
            else:
                print("Invalid index.")
        except ValueError:
            print("Invalid input.")
    
    def _cmd_send(self, message):
        """
        Comando para enviar uma mensagem ao Sink.
        
        :param message: Conteúdo da mensagem a ser enviada.
        """
        if not message:
            print("Usage: send <message>")
            return
        
        if not self.node.router.sink_nid:
            print("✗ Cannot send: Sink NID unknown")
            return
        
        print(f"Sending message to sink...")
        success = self.node.send_to_sink(message)
        
        if success:
            print("✓ Message sent")
        else:
            print("✗ Failed to send message")
    
    def _cmd_quit(self):
        """
        Encerra a aplicação CLI e o nó.
        """
        print("\nShutting down...")
        self.running = False
        self.node.running = False