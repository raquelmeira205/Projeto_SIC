
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Mock system dependencies before importing project modules
sys.modules['pydbus'] = MagicMock()
sys.modules['gi.repository'] = MagicMock()
sys.modules['gi.repository.GLib'] = MagicMock()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from node.ble_manager import BLEManager

class TestFailover(unittest.TestCase):
    def setUp(self):
        self.node_nid = b'\xAA'*16
        self.ble = BLEManager(self.node_nid)
        
        # Mock callbacks
        self.ble.router_callback_connect = MagicMock()
        self.ble.update_advertisement = MagicMock()
        
    @patch('node.ble_manager.scan_nearby_devices')
    @patch('node.ble_manager.BLEManager.connect_to_device')
    @patch('node.ble_manager.get_device_object')
    def test_find_uplink_sorting(self, mock_get_dev, mock_connect, mock_scan):
        # Mock Scan Results: 3 devices
        # (mac, name, hop, rssi, nid)
        # dev1: hop=2, rssi=-80 (Worst)
        # dev2: hop=1, rssi=-90 (Better hop, bad rssi)
        # dev3: hop=1, rssi=-50 (Best hop, best rssi)
        
        mock_scan.return_value = [
             ('mac1', 'Node1', 2, -80, b'\x01'),
             ('mac2', 'Node2', 1, -90, b'\x02'),
             ('mac3', 'Node3', 1, -50, b'\x03')
        ]
        
        # Connect always succeeds
        mock_connect.return_value = True
        
        # Run find_and_connect
        ret = self.ble.find_and_connect_uplink()
        
        self.assertTrue(ret)
        
        # Verify it chose mac3 (Best)
        self.assertEqual(self.ble.uplink_addr, 'mac3')
        
        # Verify candidates list sorted correctly
        # [mac3 (-50, hop1), mac2 (-90, hop1), mac1 (-80, hop2)]
        self.assertEqual(self.ble.uplink_candidates[0][0], 'mac3')
        self.assertEqual(self.ble.uplink_candidates[1][0], 'mac2')
        self.assertEqual(self.ble.uplink_candidates[2][0], 'mac1')
        
    @patch('node.ble_manager.scan_nearby_devices')
    @patch('node.ble_manager.BLEManager.connect_to_device')
    def test_failover(self, mock_connect, mock_scan):
        # Scan returns 2 devices
        mock_scan.return_value = [
             ('mac1', 'SinkA', 0, -50, b'\x0A'),
             ('mac2', 'SinkB', 0, -60, b'\x0B')
        ]
        
        # First connect (to mac1) succeeds
        mock_connect.side_effect = [True, True]
        
        self.ble.find_and_connect_uplink()
        self.assertEqual(self.ble.uplink_addr, 'mac1')
        
        # Simulate Monitor Disconnection triggering failover
        # We assume mac1 failed.
        # Calling failover_uplink().
        # It should try next candidate (mac2).
        
        ret = self.ble.failover_uplink()
        self.assertTrue(ret)
        self.assertEqual(self.ble.uplink_addr, 'mac2')
        self.assertEqual(self.ble.uplink_nid, b'\x0B')
        
        # Verify connect called twice
        # 1. find_and_connect -> mac1
        # 2. failover -> mac2
        self.assertEqual(mock_connect.call_count, 2)
        mock_connect.assert_any_call('mac2')

if __name__ == '__main__':
    unittest.main()
