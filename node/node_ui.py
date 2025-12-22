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
            except Exception as e:
                with open("ui_error.log", "a") as f:
                    f.write(f"{time.ctime()} UI Error: {e}\n")

            time.sleep(0.05)

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
        stdscr.clear()
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
        row = 7
        for dev in self.scan_results[:15]: 
             name = dev.get('name')
             mac = dev.get('mac', 'Unknown')
             if not name:
                 name = mac
             hop = dev.get('hop_count', -1)
             rssi = dev.get('rssi', 0)
             # Show a bit more info: Name (Hop: X, RSSI: Y)
             self._safe_addstr(row, 40, f"  {name} (Hop:{hop} RSSI:{rssi})")
             row += 1

        # Logs
        self._safe_addstr(13, 0, "Logs:", curses.A_BOLD)
        row = 14
        for l in self.logs:
            if row < h - 1:
                self._safe_addstr(row, 0, l)
                row += 1

        # Controls
        self._safe_addstr(h-1, 0, "[q] Quit  [r] Reset Stats", curses.A_REVERSE)

        stdscr.refresh()
