"""
DTLS cryptographic utilities for end-to-end security.

This module provides AEAD encryption/decryption and anti-replay protection
following the DTLS 1.2 model (RFC 6347).
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hmac

class DtlsCrypto:
    """DTLS cryptographic operations using AES-GCM"""
    
    @staticmethod
    def derive_keys(master_secret, client_random, server_random):
        """
        Derive encryption keys and IVs from master secret using HKDF.
        
        Following TLS 1.2 key derivation but simplified:
        - client_write_key (16 bytes for AES-128)
        - server_write_key (16 bytes for AES-128)
        - client_write_iv (4 bytes fixed part)
        - server_write_iv (4 bytes fixed part)
        
        Args:
            master_secret: 32-byte master secret from ECDH
            client_random: 32-byte client random
            server_random: 32-byte server random
            
        Returns:
            (client_write_key, server_write_key, client_write_iv, server_write_iv)
        """
        # Key material = 16 + 16 + 4 + 4 = 40 bytes
        key_material_length = 40
        
        # Derive key material using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_material_length,
            salt=server_random + client_random,
            info=b"dtls-key-expansion",
            backend=default_backend()
        )
        
        key_material = hkdf.derive(master_secret)
        
        # Split key material
        client_write_key = key_material[0:16]
        server_write_key = key_material[16:32]
        client_write_iv = key_material[32:36]
        server_write_iv = key_material[36:40]
        
        return client_write_key, server_write_key, client_write_iv, server_write_iv
    
    @staticmethod
    def encrypt_record(plaintext, key, iv_base, epoch, seq_number, aad):
        """
        Encrypt DTLS record using AES-GCM.
        
        Args:
            plaintext: Data to encrypt
            key: 16-byte AES key
            iv_base: 4-byte fixed IV part
            epoch: 2-byte epoch value
            seq_number: 6-byte sequence number
            aad: Additional Authenticated Data (DTLS record header)
            
        Returns:
            ciphertext || tag (16 bytes)
        """
        # Construct nonce: fixed_iv (4) || epoch (2) || seq (6) = 12 bytes
        nonce = iv_base + epoch.to_bytes(2, 'big') + seq_number.to_bytes(6, 'big')
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        
        return ciphertext_with_tag
    
    @staticmethod
    def decrypt_record(ciphertext_with_tag, key, iv_base, epoch, seq_number, aad):
        """
        Decrypt DTLS record using AES-GCM.
        
        Args:
            ciphertext_with_tag: Encrypted data with authentication tag
            key: 16-byte AES key
            iv_base: 4-byte fixed IV part
            epoch: 2-byte epoch value
            seq_number: 6-byte sequence number
            aad: Additional Authenticated Data (DTLS record header)
            
        Returns:
            plaintext
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        # Construct nonce
        nonce = iv_base + epoch.to_bytes(2, 'big') + seq_number.to_bytes(6, 'big')
        
        # Decrypt and verify with AES-GCM
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        
        return plaintext
    
    @staticmethod
    def compute_verify_data(master_secret, handshake_messages, label):
        """
        Compute verify_data for Finished message.
        
        verify_data = HMAC-SHA256(master_secret, label || handshake_messages)
        
        Args:
            master_secret: 32-byte master secret
            handshake_messages: Concatenated handshake messages
            label: b"client finished" or b"server finished"
            
        Returns:
            32-byte verify_data
        """
        return hmac.new(
            master_secret,
            label + handshake_messages,
            hashes.SHA256()
        ).digest()

class ReplayWindow:
    """
    Sliding window for DTLS anti-replay protection.
    
    Based on RFC 6347 Section 4.1.2.6
    Uses a 64-bit bitmap to track received sequence numbers.
    """
    
    def __init__(self, window_size=64):
        """
        Initialize replay window.
        
        Args:
            window_size: Size of the sliding window (default 64)
        """
        self.window_size = window_size
        self.right_edge = 0  # Highest sequence number accepted
        self.bitmap = 0      # 64-bit bitmap of received packets
    
    def check_and_update(self, seq_number):
        """
        Check if sequence number is valid and update window.
        
        Args:
            seq_number: Sequence number to check
            
        Returns:
            True if packet should be accepted, False if replay detected
        """
        # Case 1: Sequence number is to the right of the window (new)
        if seq_number > self.right_edge:
            # Shift bitmap left
            shift = min(seq_number - self.right_edge, self.window_size)
            self.bitmap <<= shift
            
            # Keep only window_size bits
            self.bitmap &= (1 << self.window_size) - 1
            
            # Mark new sequence number as received
            self.bitmap |= 1
            
            # Update right edge
            self.right_edge = seq_number
            return True
        
        # Case 2: Sequence number is within the window
        diff = self.right_edge - seq_number
        if diff < self.window_size:
            # Check if already received
            if self.bitmap & (1 << diff):
                return False  # Replay detected!
            
            # Mark as received
            self.bitmap |= (1 << diff)
            return True
        
        # Case 3: Sequence number is to the left of the window (too old)
        return False
    
    def reset(self):
        """Reset the replay window (e.g., after epoch change)"""
        self.right_edge = 0
        self.bitmap = 0
    
    def __repr__(self):
        return f"ReplayWindow(right_edge={self.right_edge}, bitmap={bin(self.bitmap)})"
