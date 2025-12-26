
import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import io

# MOCK pydbus BEFORE importing project modules
sys.modules["pydbus"] = MagicMock()
sys.modules["gi.repository"] = MagicMock()

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can safely import project modules
from common.packet_structs import PacketHeader, MsgType
from common.crypto_utils import generate_mac
# We need to ensure we can import sink.main without it exploding
# sink.main imports bluez_classes, which imports pydbus (now mocked)
from sink.main import RxCharacteristic

class MockSinkConnectionManager:
    def __init__(self):
        self.session_keys = {}
        self.replay_counters = {}

class TestInboxService(unittest.TestCase):
    def setUp(self):
        self.conn_manager = MockSinkConnectionManager()
        # Mock GLib/BlueZ stuff for RxCharacteristic
        self.mock_bus = MagicMock()
        self.mock_service = MagicMock()
        
        self.rx_char = RxCharacteristic(self.mock_bus, 0, self.mock_service, self.conn_manager)
        
        # Test Data
        self.test_mac = "11:22:33:44:55:66"
        self.test_nid = b'\x01' * 16 # Node NID
        self.sink_nid = b'\x00' * 16 # Sink NID
        self.session_key = b'secret_session_key_32_bytes_long' # 32 bytes
        
        # Setup session
        self.conn_manager.session_keys[self.test_mac] = self.session_key
        self.conn_manager.replay_counters[self.test_mac] = 0

    def test_receive_valid_message(self):
        """Test receiving a valid encrypted DATA message"""
        msg_text = "Hello Sink World!"
        payload = msg_text.encode('utf-8')
        seq_num = 1
        
        # Create valid packet
        # 1. Pack with zero MAC
        pre_packet = PacketHeader.pack(self.test_nid, self.sink_nid, MsgType.DATA, payload, seq_num, b'\x00'*32)
        # 2. Generate MAC
        mac = generate_mac(self.session_key, pre_packet)
        # 3. Final Packet
        final_packet = PacketHeader.pack(self.test_nid, self.sink_nid, MsgType.DATA, payload, seq_num, mac)
        
        # Capture stdout to verify print output
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            # Inject packet (simulate DBus write options)
            options = {"device": f"/org/bluez/hci0/dev_{self.test_mac.replace(':', '_')}"}
            self.rx_char.WriteValue(final_packet, options)
            
            output = fake_out.getvalue()
            
        # Verify
        self.assertIn("📥 INBOX MESSAGE START", output)
        self.assertIn(f"TEXT: {msg_text}", output)
        self.assertIn(f"FROM: Node {self.test_nid.hex()[:8]}", output)
        
        # Verify Replay Counter Updated
        self.assertEqual(self.conn_manager.replay_counters[self.test_mac], 1)

    def test_replay_attack(self):
        """Test that replayed packets are rejected"""
        # Set last seen to 5
        self.conn_manager.replay_counters[self.test_mac] = 5
        
        # Try to send seq 5 (should fail, must be > 5)
        msg_text = "Replay Attack!"
        payload = msg_text.encode('utf-8')
        seq_num = 5
        
        pre_packet = PacketHeader.pack(self.test_nid, self.sink_nid, MsgType.DATA, payload, seq_num, b'\x00'*32)
        mac = generate_mac(self.session_key, pre_packet)
        final_packet = PacketHeader.pack(self.test_nid, self.sink_nid, MsgType.DATA, payload, seq_num, mac)
        
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            options = {"device": f"/org/bluez/hci0/dev_{self.test_mac.replace(':', '_')}"}
            self.rx_char.WriteValue(final_packet, options)
            output = fake_out.getvalue()
            
        self.assertIn("Security Alert: Replay detected", output)
        self.assertNotIn("INBOX MESSAGE START", output)

    def test_invalid_mac(self):
        """Test tampering with payload fails MAC check"""
        msg_text = "Original Message"
        payload = msg_text.encode('utf-8')
        seq_num = 10
        
        # Create valid packet
        pre_packet = PacketHeader.pack(self.test_nid, self.sink_nid, MsgType.DATA, payload, seq_num, b'\x00'*32)
        mac = generate_mac(self.session_key, pre_packet)
        
        # Tamper payload
        tampered_payload = b"Hacked Message!!"
        # Create packet with OLD MAC but NEW Payload
        final_packet = PacketHeader.pack(self.test_nid, self.sink_nid, MsgType.DATA, tampered_payload, seq_num, mac)
        
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            options = {"device": f"/org/bluez/hci0/dev_{self.test_mac.replace(':', '_')}"}
            self.rx_char.WriteValue(final_packet, options)
            output = fake_out.getvalue()
            
        self.assertIn("Security Alert: Invalid MAC", output)
        self.assertNotIn("INBOX MESSAGE START", output)

if __name__ == '__main__':
    unittest.main()
