
import sys
import os
import unittest
from unittest.mock import MagicMock
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.security_handshake import SecurityHandshake
from common.crl_manager import CRLManager

class TestCRL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate CA
        cls.ca_key = ec.generate_private_key(ec.SECP521R1())
        cls.ca_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA")])
        ).public_key(
            cls.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).sign(cls.ca_key, hashes.SHA512())

        # Generate Node Key and Cert
        cls.node_key = ec.generate_private_key(ec.SECP521R1())
        cls.target_serial = 123456789
        cls.node_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test Node")])
        ).issuer_name(
            cls.ca_cert.subject
        ).public_key(
            cls.node_key.public_key()
        ).serial_number(
            cls.target_serial 
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).sign(cls.ca_key, hashes.SHA512())

        # Save to temp files
        with open("test_ca.crt", "wb") as f:
            f.write(cls.ca_cert.public_bytes(serialization.Encoding.PEM))
        with open("test_node.crt", "wb") as f:
            f.write(cls.node_cert.public_bytes(serialization.Encoding.PEM))
        with open("test_node.key", "wb") as f:
            f.write(cls.node_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    @classmethod
    def tearDownClass(cls):
        # Cleanup
        for f in ["test_ca.crt", "test_node.crt", "test_node.key", "test_crl.json"]:
            if os.path.exists(f):
                os.remove(f)

    def test_revocation(self):
        # 1. Create CRL Manager
        crl_manager = CRLManager("test_crl.json")
        
        # 2. Revoke the target serial
        crl_manager.revoke(self.target_serial)
        
        # 3. Init Handshake with CRL Manager
        handshake = SecurityHandshake("test_node.crt", "test_node.key", "test_ca.crt", crl_manager)
        
        # 4. Simulate receiving the revoked cert (manually setting peer_cert)
        handshake.peer_cert = self.node_cert
        
        # 5. Verify should fail
        with self.assertRaises(ValueError) as cm:
            handshake.verify_peer_certificate()
        
        print(f"\nCaught Expected Error: {cm.exception}")
        self.assertIn("CERTIFICADO REVOGADO", str(cm.exception))

    def test_valid_cert(self):
        # 1. Create CRL Manager (Empty)
        if os.path.exists("test_crl.json"): os.remove("test_crl.json")
        crl_manager = CRLManager("test_crl.json")
        
        # 2. Init Handshake
        handshake = SecurityHandshake("test_node.crt", "test_node.key", "test_ca.crt", crl_manager)
        handshake.peer_cert = self.node_cert
        
        # 3. Verify should pass
        try:
            handshake.verify_peer_certificate()
        except Exception as e:
            self.fail(f"Verification failed for valid cert: {e}")

if __name__ == '__main__':
    unittest.main()
