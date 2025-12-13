import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# We need to import Node inside the test or patch it where it is imported.
# It is better to rely on patch strings.

class TestForceConnect(unittest.TestCase):
    @patch('node.main.BLEManager')
    @patch('node.main.Router')
    @patch('node.main.NodeApplication')
    def test_force_connect(self, MockApp, MockRouter, MockBLE):
        from node.main import Node
        
        # Setup Mock Instance
        ble_instance = MockBLE.return_value
        ble_instance.connect_to_device.return_value = True
        # Explicitly ensure these exist (MagicMock should do it, but to be sure)
        ble_instance.set_router_callbacks = MagicMock()
        ble_instance.start_advertising = MagicMock()
        
        nid = b'\x01' * 16
        n = Node(nid)
        
        # Check if Node used our mock
        self.assertEqual(n.ble_manager, ble_instance)
        
        # Test force_connect
        target_mac = "AA:BB:CC:DD:EE:FF"
        res = n.force_connect(target_mac)
        
        self.assertTrue(res)
        ble_instance.connect_to_device.assert_called_with(target_mac)
        
        # Verify manually set properties
        self.assertEqual(ble_instance.uplink_addr, target_mac)
        self.assertEqual(ble_instance.uplink_nid, b'\x00'*16)
        self.assertEqual(ble_instance.hop_count, 255)
        
        print("\nSUCCESS: Force Connect Verified")

if __name__ == "__main__":
    unittest.main()
