
import sys
import os
import time
import unittest

# Add root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sink.rate_limiter import RateLimiter
from common.packet_structs import MsgType

class TestRateLimiter(unittest.TestCase):
    def test_bucket_capacity(self):
        limiter = RateLimiter()
        # Override config for testing: 5 max, 1 per sec
        limiter.limits_config[MsgType.DATA] = (5, 1.0)
        
        nid = b'\x01'*16
        
        # Consume 5
        for i in range(5):
            self.assertTrue(limiter.check_rate_limit(nid, MsgType.DATA), f"Msg {i} should pass")
            
        # 6th should fail
        self.assertFalse(limiter.check_rate_limit(nid, MsgType.DATA), "Msg 6 should block")
        
    def test_bucket_refill(self):
        limiter = RateLimiter()
        # 2 max, 10 per sec (fast refill)
        limiter.limits_config[MsgType.DATA] = (2, 10.0)
        
        nid = b'\x02'*16
        
        # Consume all
        self.assertTrue(limiter.check_rate_limit(nid, MsgType.DATA))
        self.assertTrue(limiter.check_rate_limit(nid, MsgType.DATA))
        self.assertFalse(limiter.check_rate_limit(nid, MsgType.DATA))
        
        # Wait 0.15s (should refill 1.5 -> 1 token)
        time.sleep(0.15)
        
        # Should pass
        self.assertTrue(limiter.check_rate_limit(nid, MsgType.DATA))
        
    def test_nid_separation(self):
        limiter = RateLimiter()
        limiter.limits_config[MsgType.DATA] = (1, 1.0)
        
        nid1 = b'\x01'*16
        nid2 = b'\x02'*16
        
        self.assertTrue(limiter.check_rate_limit(nid1, MsgType.DATA))
        self.assertFalse(limiter.check_rate_limit(nid1, MsgType.DATA))
        
        # Node 2 should be fresh
        self.assertTrue(limiter.check_rate_limit(nid2, MsgType.DATA))

if __name__ == '__main__':
    unittest.main()
