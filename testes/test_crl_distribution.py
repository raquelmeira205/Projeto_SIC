
import sys
import os
import unittest
import json
from unittest.mock import MagicMock, patch

# MOCK D-BUS BEFORE IMPORTING PROJECT MODULES
sys.modules["pydbus"] = MagicMock()
sys.modules["gi"] = MagicMock()
sys.modules["gi.repository"] = MagicMock()
sys.modules["gi.repository.GLib"] = MagicMock()

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from node.router import Router
from common.packet_structs import MsgType

class TestCRLDistribution(unittest.TestCase):
    def setUp(self):
        # Mock dependencies
        self.mock_security = MagicMock()
        self.mock_ble = MagicMock()
        
        # Initialize Router
        # We need to mock CRLManager so we don't write to actual files during test
        with patch('node.router.CRLManager') as MockCRLManager:
            self.router = Router("NODE_A", self.mock_security, self.mock_ble)
            self.mock_crl_manager = MockCRLManager.return_value
            self.router.crl_manager = self.mock_crl_manager

        # Setup downlink
        self.router.downlink_connections.add("NODE_B_CONN")
        self.router.link_keys["NODE_B_CONN"] = b'1234' # Mock Link Key

    def test_receive_crl_update(self):
        # 1. Simulate CONTROL packet with CRL update
        revoked_serials = [12345, 67890]
        crl_payload = json.dumps({"type": "crl", "revoked": list(reversed(revoked_serials))}).encode('utf-8')
        
        # 2. Call process_incoming_packet (mocking PacketHeader unpack)
        # We mock PacketHeader inside process_incoming_packet implicitly by controlling flow or mocking the class
        # But easier to just call the logic block directly or test via side effects
        
        # Let's interact with router.process_incoming_packet
        # We need to constructing a valid packet is hard without the real key for MAC.
        # So we mock PacketHeader.unpack to return what we want.
        
        with patch('common.packet_structs.PacketHeader.unpack') as mock_unpack:
            # src, dest, mtype, payload, seq, mac
            mock_unpack.return_value = (b'SINK', b'NODE_A', MsgType.CONTROL, crl_payload, 1, b'MAC')
            
            # Mock _verify_security to always return True
            self.router._verify_security = MagicMock(return_value=True)
            
            # Mock _send_authenticated_packet to verify forwarding
            self.router._send_authenticated_packet = MagicMock()

            # Mock crl_manager.update_from_list to return True (indicating update happened)
            self.mock_crl_manager.update_from_list.return_value = True

            # Action
            self.router.process_incoming_packet(b'some_data', "UPLINK_CONN")
            
            # Assertions
            # 1. verify CRL Manager was updated
            # Note: The router calls set(int(s)...) inside CRLManager usually, 
            # here we mocked update_from_list calls.
            # Convert list items to whatever logic router uses.
            # In router implementation: 
            # revoked = data.get("revoked", [])
            # self.crl_manager.update_from_list(revoked)
            
            # Check if update_from_list was called with the list from JSON
            args, _ = self.mock_crl_manager.update_from_list.call_args
            # The order in JSON list might vary but we passed [67890, 12345] (reversed)
            self.assertCountEqual(args[0], list(reversed(revoked_serials)))
            
            # 2. Verify forwarding to downlink
            self.router._send_authenticated_packet.assert_called_with(
                "NODE_B_CONN", 
                b'SINK', 
                b'\xff'*16, # dest placeholder 
                MsgType.CONTROL, 
                crl_payload
            )
            print("CRL Update correctly processed and forwarded!")

if __name__ == '__main__':
    unittest.main()
