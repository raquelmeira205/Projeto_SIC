import time
from common.packet_structs import MsgType

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate # tokens per second
        self.last_update = time.time()

    def consume(self, tokens=1):
        now = time.time()
        elapsed = now - self.last_update
        
        # Refill
        added_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + added_tokens)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        else:
            return False

class RateLimiter:
    def __init__(self):
        # Configuration: (capacity, refill_rate)
        # 10 msg burst, 2 msg/sec sustained (example)
        self.DEFAULT_LIMIT = (10, 5.0) 
        
        # Specific limits by message type
        self.limits_config = {
             MsgType.DATA: (20, 10.0),      # High troughput for data
             MsgType.HEARTBEAT: (5, 0.5),   # Low rate allowed (shouldn't receive many from nodes anyway)
             MsgType.CONTROL: (5, 1.0),     # Control messages
             MsgType.DTLS_HANDSHAKE: (10, 2.0) # Allow burst for handshake
        }
        
        # Map: nid (bytes) -> { msg_type -> TokenBucket }
        self.buckets = {} 
        
    def check_rate_limit(self, nid_bytes, msg_type):
        """
        Check if message from nid of type msg_type allows passage.
        Returns True if allowed, False if blocked.
        """
        if not nid_bytes:
            return True # Allow unknown (or handle separate?)
            
        if nid_bytes not in self.buckets:
            self.buckets[nid_bytes] = {}
            
        node_buckets = self.buckets[nid_bytes]
        
        if msg_type not in node_buckets:
            # Create new bucket for this type
            capacity, rate = self.limits_config.get(msg_type, self.DEFAULT_LIMIT)
            node_buckets[msg_type] = TokenBucket(capacity, rate)
            
        return node_buckets[msg_type].consume(1)

    def cleanup(self, max_idle_time=300):
        """Optional: clear old entries to save memory"""
        now = time.time()
        # TODO: Implement cleanup if needed
        pass
