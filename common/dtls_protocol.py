"""
DTLS-Like Protocol Messages

Implements DTLS-style handshake messages for end-to-end encryption.
Following DTLS principles but adapted for our BLE/Router transport.
"""

from enum import IntEnum
from dataclasses import dataclass
import struct


class DTLSMessageType(IntEnum):
    """DTLS-like handshake message types"""
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 3
    CERTIFICATE_REQUEST = 4
    CERTIFICATE_VERIFY = 5
    FINISHED = 6
    APPLICATION_DATA = 7


@dataclass
class ClientHello:
    """
    Client Hello message
    
    Sent by Node to initiate DTLS session with Sink
    """
    client_random: bytes  # 32 bytes
    client_nid: bytes     # 16 bytes (128-bit NID)
    ecdh_public_key: bytes  # Client's ephemeral ECDH public key
    
    def pack(self) -> bytes:
        """Pack ClientHello into bytes"""
        # Format: type(1) + client_random(32) + client_nid(16) + key_len(2) + key
        key_len = len(self.ecdh_public_key)
        return struct.pack(
            f'!B32s16sH{key_len}s',
            DTLSMessageType.CLIENT_HELLO,
            self.client_random,
            self.client_nid,
            key_len,
            self.ecdh_public_key
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'ClientHello':
        """Unpack ClientHello from bytes"""
        msg_type, client_random, client_nid, key_len = struct.unpack('!B32s16sH', data[:51])
        ecdh_public_key = data[51:51+key_len]
        return ClientHello(client_random, client_nid, ecdh_public_key)


@dataclass
class ServerHello:
    """
    Server Hello message
    
    Sent by Sink in response to ClientHello
    """
    server_random: bytes  # 32 bytes
    server_nid: bytes     # 16 bytes (Sink's NID, all zeros)
    ecdh_public_key: bytes  # Server's ephemeral ECDH public key
    server_certificate: bytes  # DER-encoded X.509 certificate
    
    def pack(self) -> bytes:
        """Pack ServerHello into bytes"""
        key_len = len(self.ecdh_public_key)
        cert_len = len(self.server_certificate)
        return struct.pack(
            f'!B32s16sH{key_len}sI{cert_len}s',
            DTLSMessageType.SERVER_HELLO,
            self.server_random,
            self.server_nid,
            key_len,
            self.ecdh_public_key,
            cert_len,
            self.server_certificate
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'ServerHello':
        """Unpack ServerHello from bytes"""
        msg_type, server_random, server_nid, key_len = struct.unpack('!B32s16sH', data[:51])
        offset = 51
        ecdh_public_key = data[offset:offset+key_len]
        offset += key_len
        cert_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        server_certificate = data[offset:offset+cert_len]
        return ServerHello(server_random, server_nid, ecdh_public_key, server_certificate)


@dataclass
class Certificate:
    """
    Certificate message
    
    Sent by Node to provide its certificate to Sink
    """
    certificate: bytes  # DER-encoded X.509 certificate
    
    def pack(self) -> bytes:
        """Pack Certificate into bytes"""
        cert_len = len(self.certificate)
        return struct.pack(
            f'!BI{cert_len}s',
            DTLSMessageType.CERTIFICATE,
            cert_len,
            self.certificate
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'Certificate':
        """Unpack Certificate from bytes"""
        msg_type, cert_len = struct.unpack('!BI', data[:5])
        certificate = data[5:5+cert_len]
        return Certificate(certificate)


@dataclass
class CertificateVerify:
    """
    Certificate Verify message
    
    Proves possession of private key by signing handshake transcript
    """
    signature: bytes  # ECDSA signature over handshake transcript
    
    def pack(self) -> bytes:
        """Pack CertificateVerify into bytes"""
        sig_len = len(self.signature)
        return struct.pack(
            f'!BH{sig_len}s',
            DTLSMessageType.CERTIFICATE_VERIFY,
            sig_len,
            self.signature
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'CertificateVerify':
        """Unpack CertificateVerify from bytes"""
        msg_type, sig_len = struct.unpack('!BH', data[:3])
        signature = data[3:3+sig_len]
        return CertificateVerify(signature)


@dataclass
class Finished:
    """
    Finished message
    
    Confirms handshake completion with MAC over all handshake messages
    """
    verify_data: bytes  # HMAC over handshake transcript
    
    def pack(self) -> bytes:
        """Pack Finished into bytes"""
        return struct.pack(
            f'!B32s',
            DTLSMessageType.FINISHED,
            self.verify_data
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'Finished':
        """Unpack Finished from bytes"""
        msg_type, verify_data = struct.unpack('!B32s', data[:33])
        return Finished(verify_data)


@dataclass
class DTLSRecord:
    """
    DTLS-like record for application data
    
    Contains encrypted application data with AEAD protection
    """
    epoch: int  # 2 bytes - Key epoch (for rekeying)
    sequence_number: int  # 8 bytes - Sequence number for replay protection
    content_type: int  # 1 byte - Content type (APPLICATION_DATA)
    version: int  # 2 bytes - Protocol version
    ciphertext: bytes  # Encrypted data
    auth_tag: bytes  # 16 bytes - GCM authentication tag
    
    def pack(self) -> bytes:
        """Pack DTLS record into bytes"""
        # Format: epoch(2) + seq(8) + type(1) + version(2) + length(2) + ciphertext + tag(16)
        length = len(self.ciphertext)
        return struct.pack(
            f'!HQBHH{length}s16s',
            self.epoch,
            self.sequence_number,
            self.content_type,
            self.version,
            length,
            self.ciphertext,
            self.auth_tag
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'DTLSRecord':
        """Unpack DTLS record from bytes"""
        epoch, seq, content_type, version, length = struct.unpack('!HQBHH', data[:15])
        ciphertext = data[15:15+length]
        auth_tag = data[15+length:15+length+16]
        return DTLSRecord(epoch, seq, content_type, version, ciphertext, auth_tag)
