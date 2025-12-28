"""
DTLS-like protocol structures for end-to-end security.

This module implements DTLS-like message types and record format
following the DTLS 1.2 model (RFC 6347) adapted for our Router protocol.
"""

import struct
from enum import IntEnum

class DtlsContentType(IntEnum):
    """DTLS Content Types (RFC 6347 Section 4)"""
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    ALERT = 21

class DtlsHandshakeType(IntEnum):
    """DTLS Handshake Message Types"""
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

class DtlsVersion:
    """DTLS Version 1.2"""
    MAJOR = 0xFE
    MINOR = 0xFD  # DTLS 1.2 = {254, 253}

class DtlsRecord:
    """
    DTLS Record Layer structure (RFC 6347 Section 4.1)
    
    struct {
        ContentType type;
        ProtocolVersion version;
        uint16 epoch;
        uint48 sequence_number;
        uint16 length;
        opaque fragment[DTLSPlaintext.length];
    } DTLSPlaintext;
    
    After encryption with AEAD:
    - fragment becomes ciphertext || auth_tag (16 bytes)
    """
    
    HEADER_SIZE = 13  # 1 + 2 + 2 + 6 + 2
    TAG_SIZE = 16     # AES-GCM authentication tag
    
    @staticmethod
    def pack_header(content_type, epoch, seq_number, length):
        """
        Pack DTLS record header.
        
        Args:
            content_type: DtlsContentType
            epoch: 2-byte epoch value
            seq_number: 6-byte sequence number
            length: 2-byte payload length
            
        Returns:
            13-byte header
        """
        return struct.pack(
            '!BBBHH',
            content_type,
            DtlsVersion.MAJOR,
            DtlsVersion.MINOR,
            epoch,
            length
        ) + seq_number.to_bytes(6, 'big')
    
    @staticmethod
    def unpack_header(data):
        """
        Unpack DTLS record header.
        
        Returns:
            (content_type, epoch, seq_number, length)
        """
        if len(data) < DtlsRecord.HEADER_SIZE:
            raise ValueError("Data too short for DTLS header")
        
        content_type, major, minor, epoch, length = struct.unpack('!BBBHH', data[:7])
        seq_number = int.from_bytes(data[7:13], 'big')
        
        if major != DtlsVersion.MAJOR or minor != DtlsVersion.MINOR:
            raise ValueError(f"Invalid DTLS version: {major}.{minor}")
        
        return content_type, epoch, seq_number, length
    
    @staticmethod
    def pack(content_type, epoch, seq_number, payload):
        """
        Pack complete DTLS record (header + payload).
        
        Args:
            content_type: DtlsContentType
            epoch: Current epoch
            seq_number: Sequence number
            payload: Encrypted data (ciphertext + tag for APPLICATION_DATA)
            
        Returns:
            Complete DTLS record bytes
        """
        header = DtlsRecord.pack_header(content_type, epoch, seq_number, len(payload))
        return header + payload
    
    @staticmethod
    def unpack(data):
        """
        Unpack DTLS record.
        
        Returns:
            (content_type, epoch, seq_number, payload)
        """
        content_type, epoch, seq_number, length = DtlsRecord.unpack_header(data)
        
        if len(data) < DtlsRecord.HEADER_SIZE + length:
            raise ValueError("Incomplete DTLS record")
        
        payload = data[DtlsRecord.HEADER_SIZE:DtlsRecord.HEADER_SIZE + length]
        return content_type, epoch, seq_number, payload

class DtlsHandshakeMessage:
    """
    DTLS Handshake Message structure.
    
    struct {
        HandshakeType msg_type;
        uint24 length;
        uint16 message_seq;
        uint24 fragment_offset;
        uint24 fragment_length;
        opaque fragment[fragment_length];
    } Handshake;
    """
    
    HEADER_SIZE = 12  # 1 + 3 + 2 + 3 + 3
    
    @staticmethod
    def pack(msg_type, message_seq, fragment):
        """
        Pack handshake message (no fragmentation support).
        
        Args:
            msg_type: DtlsHandshakeType
            message_seq: Handshake message sequence number
            fragment: Message payload
            
        Returns:
            Handshake message bytes
        """
        length = len(fragment)
        
        return struct.pack(
            '!B',
            msg_type
        ) + length.to_bytes(3, 'big') + struct.pack(
            '!H',
            message_seq
        ) + (0).to_bytes(3, 'big') + length.to_bytes(3, 'big') + fragment
    
    @staticmethod
    def unpack(data):
        """
        Unpack handshake message.
        
        Returns:
            (msg_type, message_seq, fragment)
        """
        if len(data) < DtlsHandshakeMessage.HEADER_SIZE:
            raise ValueError("Data too short for handshake message")
        
        msg_type = data[0]
        length = int.from_bytes(data[1:4], 'big')
        message_seq = struct.unpack('!H', data[4:6])[0]
        fragment_offset = int.from_bytes(data[6:9], 'big')
        fragment_length = int.from_bytes(data[9:12], 'big')
        
        if fragment_offset != 0 or fragment_length != length:
            raise ValueError("Fragmented handshake messages not supported")
        
        fragment = data[12:12 + fragment_length]
        return msg_type, message_seq, fragment

class ClientHello:
    """ClientHello handshake message payload"""
    
    @staticmethod
    def pack(client_random, client_nid, ecdh_public_key):
        """
        Pack ClientHello.
        
        Args:
            client_random: 32 bytes random
            client_nid: 16 bytes Network ID
            ecdh_public_key: ECDH public key bytes (PEM format)
            
        Returns:
            ClientHello payload
        """
        return client_random + client_nid + len(ecdh_public_key).to_bytes(2, 'big') + ecdh_public_key
    
    @staticmethod
    def unpack(data):
        """
        Unpack ClientHello.
        
        Returns:
            (client_random, client_nid, ecdh_public_key)
        """
        if len(data) < 50:  # 32 + 16 + 2 minimum
            raise ValueError("ClientHello too short")
        
        client_random = data[:32]
        client_nid = data[32:48]
        key_len = int.from_bytes(data[48:50], 'big')
        ecdh_public_key = data[50:50 + key_len]
        
        return client_random, client_nid, ecdh_public_key

class ServerHello:
    """ServerHello handshake message payload"""
    
    @staticmethod
    def pack(server_random, server_nid, ecdh_public_key, certificate_pem):
        """
        Pack ServerHello + Certificate.
        
        Args:
            server_random: 32 bytes random
            server_nid: 16 bytes Network ID
            ecdh_public_key: ECDH public key bytes (PEM format)
            certificate_pem: Server certificate (PEM format)
            
        Returns:
            ServerHello payload
        """
        return (
            server_random + 
            server_nid + 
            len(ecdh_public_key).to_bytes(2, 'big') + 
            ecdh_public_key +
            len(certificate_pem).to_bytes(2, 'big') +
            certificate_pem
        )
    
    @staticmethod
    def unpack(data):
        """
        Unpack ServerHello.
        
        Returns:
            (server_random, server_nid, ecdh_public_key, certificate_pem)
        """
        if len(data) < 52:  # 32 + 16 + 2 + 2 minimum
            raise ValueError("ServerHello too short")
        
        server_random = data[:32]
        server_nid = data[32:48]
        
        key_len = int.from_bytes(data[48:50], 'big')
        ecdh_public_key = data[50:50 + key_len]
        
        cert_len = int.from_bytes(data[50 + key_len:52 + key_len], 'big')
        certificate_pem = data[52 + key_len:52 + key_len + cert_len]
        
        return server_random, server_nid, ecdh_public_key, certificate_pem

class ClientKeyExchange:
    """ClientKeyExchange + Certificate + CertificateVerify combined"""
    
    @staticmethod
    def pack(certificate_pem, signature):
        """
        Pack client certificate and signature over handshake transcript.
        
        Args:
            certificate_pem: Client certificate (PEM format)
            signature: Signature over transcript
            
        Returns:
            ClientKeyExchange payload
        """
        return (
            len(certificate_pem).to_bytes(2, 'big') +
            certificate_pem +
            len(signature).to_bytes(2, 'big') +
            signature
        )
    
    @staticmethod
    def unpack(data):
        """
        Unpack ClientKeyExchange.
        
        Returns:
            (certificate_pem, signature)
        """
        if len(data) < 4:
            raise ValueError("ClientKeyExchange too short")
        
        cert_len = int.from_bytes(data[:2], 'big')
        certificate_pem = data[2:2 + cert_len]
        
        sig_len = int.from_bytes(data[2 + cert_len:4 + cert_len], 'big')
        signature = data[4 + cert_len:4 + cert_len + sig_len]
        
        return certificate_pem, signature

class Finished:
    """Finished handshake message"""
    
    @staticmethod
    def pack(verify_data):
        """
        Pack Finished message.
        
        Args:
            verify_data: HMAC over handshake transcript (32 bytes)
            
        Returns:
            Finished payload
        """
        return verify_data
    
    @staticmethod
    def unpack(data):
        """
        Unpack Finished message.
        
        Returns:
            verify_data
        """
        if len(data) != 32:
            raise ValueError("Finished verify_data must be 32 bytes")
        return data
