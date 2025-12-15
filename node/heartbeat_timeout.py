
import time
import logging

class HeartbeatMonitor:
    def __init__(self, timeout_callback, timeout_sec=20):
        self.last_heartbeat = time.time()
        self.timeout_sec = timeout_sec
        self.callback = timeout_callback
        self.monitoring = False

    def heartbeat_received(self):
        self.last_heartbeat = time.time()

    def check(self):
        if not self.monitoring:
            return
            
        if (time.time() - self.last_heartbeat) > self.timeout_sec:
            logging.warning("Heartbeat Timeout Detected!")
            self.monitoring = False # Stop monitoring until reset/reconnected
            if self.callback:
                self.callback()

    def start(self):
        self.last_heartbeat = time.time()
        self.monitoring = True

    def stop(self):
        self.monitoring = False
