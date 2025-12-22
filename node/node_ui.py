import curses
import time
import threading
import signal

class NodeUI:
    def __init__(self, node_ref):
        self.node = node_ref
        self.running = False
        self.stdscr = None
        self.logs = []
        self.max_logs = 10
        self.scan_results = []
        self.selected_index = 0

        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._handle_sigint)

    def _handle_sigint(self, sig, frame):
        self.log("Ctrl+C pressed, shutting down...")
        self.running = False
        self.node.stop()

    def update_scan_results(self, results):
        self.scan_results = results
        # Trigger redraw if needed, but loop handles it

    def start(self):
        self.running = True
        # Runs in the main thread; curses.wrapper handles cleanup
        curses.wrapper(self._main_loop)

    def log(self, msg):
        self.logs.append(f"{time.strftime('%H:%M:%S')} {msg}")
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def _main_loop(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(True)
        stdscr.timeout(100)

        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)

        while self.running:
            self._draw(stdscr)

            try:
                key = stdscr.getch()
                if key != -1:
                    if key == ord('q'):
                        self.log("Quit pressed, shutting down...")
                        self.running = False
                        self.node.stop()  # Stop node safely
                    elif key == ord('r'):
                        self.node.reset_stats()
                        self.log("Stats reset")
                    elif key == curses.KEY_UP:
                        self.selected_index = max(0, self.selected_index - 1)
                    elif key == curses.KEY_DOWN:
                        self.selected_index = min(len(self.scan_results) - 1, self.selected_index + 1)
                    elif key == 10 or key == 13: # Enter
                        if 0 <= self.selected_index < len(self.scan_results):
                            candidate = self.scan_results[self.selected_index]
                            self.log(f"Selected: {candidate.get('mac')}")
                            # Connect in a separate thread to not block UI
                            threading.Thread(target=self.node.connect_manual, args=(candidate,), daemon=True).start()
            except Exception as e:
                with open("ui_error.log", "a") as f:
                    f.write(f"{time.ctime()} UI Error: {e}\n")

    def _safe_addstr(self, y, x, msg, *args):
        h, w = self.stdscr.getmaxyx()
        if y < h and x < w:
            try:
                # Truncate if too long
                available = w - x
                if len(msg) > available:
                    msg = msg[:available-1] + "…"
                self.stdscr.addstr(y, x, msg, *args)
            except curses.error:
                pass

    def _draw(self, stdscr):
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # Header
        self._safe_addstr(0, 0, f"SIC Node: {self.node.nid.hex}", curses.color_pair(3) | curses.A_BOLD)
        self._safe_addstr(0, max(0, w-20), time.strftime('%H:%M:%S'))

        # Status
        uplink = self.node.current_uplink_mac
        hop = self.node.hop_count
        status_color = curses.color_pair(1) if uplink else curses.color_pair(2)
        self._safe_addstr(2, 0, f"Uplink: {uplink if uplink else 'Disconnected'}", status_color)
        self._safe_addstr(3, 0, f"Hop Count: {hop}")
        self._safe_addstr(4, 0, f"Sink NID: {self.node.sink_nid.hex() if self.node.sink_nid else 'Unknown'}")

        # Stats
        self._safe_addstr(2, 40, f"Lost Heartbeats: {self.node.stats['lost_heartbeats']}")
        self._safe_addstr(3, 40, f"Routed Msgs: {self.node.stats['routed_messages']}")

        # Forwarding Table (show top 5)
        self._safe_addstr(6, 0, "Forwarding Table:", curses.A_BOLD)
        row = 7
        for dest, next_hop in list(self.node.forwarding_table.items())[:5]:
            self._safe_addstr(row, 0, f"  {dest.hex()} -> {next_hop}")
            row += 1

        # Scan Results
        self._safe_addstr(6, 40, "Scan Results:", curses.A_BOLD)
        
        # Calculate visual window (max 15 items)
        max_visible = 15
        start_idx = 0
        if self.selected_index >= max_visible:
            start_idx = self.selected_index - max_visible + 1
        
        visible_items = self.scan_results[start_idx : start_idx + max_visible]
        
        row = 7
        for i, dev in enumerate(visible_items):
             real_index = start_idx + i
             
             name = dev.get('name')
             mac = dev.get('mac', 'Unknown')
             if not name:
                 name = mac
             hop = dev.get('hop_count', -1)
             rssi = dev.get('rssi', 0)
             
             # Highlight selected
             style = curses.A_NORMAL
             if real_index == self.selected_index:
                 style = curses.A_REVERSE

             # Show a bit more info: Name (Hop: X, RSSI: Y)
             self._safe_addstr(row, 40, f"  {name} (Hop:{hop} RSSI:{rssi})", style)
             row += 1
             
        # Scroll indicators
        if start_idx > 0:
            self._safe_addstr(6, 60, "^")
        if start_idx + max_visible < len(self.scan_results):
            self._safe_addstr(row, 60, "v")

        # Logs
        self._safe_addstr(13, 0, "Logs:", curses.A_BOLD)
        row = 14
        for l in self.logs:
            if row < h - 1:
                self._safe_addstr(row, 0, l)
                row += 1

        # Controls
        self._safe_addstr(h-1, 0, "[q] Quit [r] Reset Stats [Arrows] Select [Enter] Connect", curses.A_REVERSE)

        stdscr.refresh()
