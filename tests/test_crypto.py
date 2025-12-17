import unittest
import sys
import os

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.crypto_utils import generate_mac, verify_mac
from common.packet_structs import PacketHeader, MsgType

class TestCrypto(unittest.TestCase):
    def test_mac_generation_verification(self):
        key = b'secret_key_1234567890123456'
        data = b'Hello World'
        
        mac = generate_mac(key, data)
        self.assertEqual(len(mac), 32)
        
        self.assertTrue(verify_mac(key, data, mac))
        self.assertFalse(verify_mac(b'wrong_key_______', data, mac))
        self.assertFalse(verify_mac(key, b'Hello World!', mac))

    def test_packet_header_security(self):
        src = b'\x01'*16
        dest = b'\x02'*16
        payload = b'Test Payload'
        seq = 100
        key = b'link_key________' * 2 # 32 bytes

        # 1. Create packet with 0 MAC
        temp_pkt = PacketHeader.pack(src, dest, MsgType.DATA, payload, seq, b'\x00'*32)
        
        # 2. Sign
        mac = generate_mac(key, temp_pkt)
        
        # 3. Final Packet
        final_pkt = PacketHeader.pack(src, dest, MsgType.DATA, payload, seq, mac)
        
        # 4. Verify
        # Reconstruct check packet
        s, d, m, p, sq, r_mac = PacketHeader.unpack(final_pkt)
        self.assertEqual(sq, seq)
        self.assertEqual(r_mac, mac)
        
        check_pkt = PacketHeader.pack(s, d, m, p, sq, b'\x00'*32)
        self.assertTrue(verify_mac(key, check_pkt, r_mac))

if __name__ == '__main__':
    unittest.main()
