import threading
import time
import sys

class NodeCLI:
    def __init__(self, node_ref):
        self.node = node_ref
        self.running = True
        self.scan_results = []
        self.last_status_time = 0
        
    def start(self):
        """Start the CLI interface"""
        print("\n" + "="*60)
        print("SIC IoT Node - Command Line Interface")
        print("="*60)
        print(f"Node NID: {self.node.node_nid.hex()}")
        print("\nType 'help' for available commands\n")
        
        # Start status monitor thread
        status_thread = threading.Thread(target=self._status_monitor, daemon=True)
        status_thread.start()
        
        # Main command loop
        self._command_loop()
    
    def _status_monitor(self):
        """Background thread to monitor and display periodic status"""
        while self.running:
            time.sleep(30)  # Update every 30 seconds
            if self.running:
                self._print_status_line()
    
    def _print_status_line(self):
        """Print a one-line status update"""
        uplink = self.node.ble_manager.uplink_addr
        hop = self.node.ble_manager.hop_count
        status = f"Connected to {uplink} (Hop:{hop})" if uplink else "Disconnected"
        print(f"\n[STATUS] {status}")
        print("> ", end="", flush=True)
    
    def _command_loop(self):
        """Main command input loop"""
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
        """Show available commands"""
        print("\nAvailable Commands:")
        print("  scan              - Scan for nearby BLE devices")
        print("  connect <index>   - Connect to device by index from scan results")
        print("  status            - Show current node status")
        print("  stats             - Show statistics")
        print("  send <message>    - Send message to sink")
        print("  help              - Show this help message")
        print("  quit              - Exit application")
        print()
    
    def _cmd_scan(self):
        """Trigger BLE scan"""
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
        """Connect to device by index"""
        if not args:
            print("Usage: connect <index>")
            return
        
        try:
            index = int(args)
        except ValueError:
            print("Invalid index. Must be a number.")
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
        """Show current node status"""
        print("\n" + "="*60)
        print("NODE STATUS")
        print("="*60)
        
        # Basic info
        print(f"Node NID:     {self.node.node_nid.hex()}")
        
        # Uplink
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
        
        # Sink
        sink_nid = self.node.router.sink_nid
        print(f"Sink NID:     {sink_nid.hex() if sink_nid else 'Unknown'}")
        
        # Forwarding table
        print(f"\nForwarding Table: {len(self.node.router.forwarding_table)} entries")
        for dest, next_hop in list(self.node.router.forwarding_table.items())[:5]:
            print(f"  {dest.hex()} -> {next_hop}")
        
        if len(self.node.router.forwarding_table) > 5:
            print(f"  ... and {len(self.node.router.forwarding_table) - 5} more")
        
        print("="*60 + "\n")
    
    def _cmd_stats(self):
        """Show statistics"""
        stats = self.node.router.stats
        
        print("\n" + "="*60)
        print("STATISTICS")
        print("="*60)
        print(f"Lost Heartbeats:  {stats['lost_heartbeats']}")
        print(f"Routed Messages:  {stats['routed_messages']}")
        print(f"Received Messages: {len(stats.get('received_messages', []))}")
        
        # Show recent messages
        messages = stats.get('received_messages', [])
        if messages:
            print("\nRecent Messages:")
            for sender, msg in messages[-5:]:
                print(f"  [{sender[:16]}...]: {msg}")
        
        print("="*60 + "\n")
    
    def _cmd_send(self, message):
        """Send message to sink"""
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
        """Exit the application"""
        print("\nShutting down...")
        self.running = False
        self.node.running = False
