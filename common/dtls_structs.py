import struct
from enum import IntEnum

# Constants
DTLS_VERSION = 0xFEFF # DTLS 1.0 (approx) for simplicity
AES_128_GCM_IV_SIZE = 12
AES_128_GCM_TAG_SIZE = 16

class ContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

class DtlsHandshakeType(IntEnum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

class DtlsRecord:
    # DTLS 1.2 Record Header:
    # ContentType(1) | Version(2) | Epoch(2) | SequenceNumber(6) | Length(2)
    # Note: SequenceNumber is actually 48-bit combined with Epoch, but on wire it's 
    # Epoch(2) + SeqNum(6). struct doesn't support 6-byte int easily.
    # We will manually handle packing logic.
    FORMAT_HDR = '!BHHQ' # We'll pack Epoch+Seq as Q (8 bytes) then mask?? No.
                         # Typical DTLS on wire: Type(1) Ver(2) Epoch(2) Seq(6) Len(2)
                         # Total 1 + 2 + 2 + 6 + 2 = 13 bytes
                         
    HEADER_SIZE = 13

    @staticmethod
    def pack(content_type, epoch, seq_num, payload):
        length = len(payload)
        
        # Manually pack because of 6-byte sequence number
        header = bytearray(13)
        header[0] = content_type
        struct.pack_into('!H', header, 1, DTLS_VERSION)
        struct.pack_into('!H', header, 3, epoch)
        
        # Pack 6-byte sequence number at offset 5
        # seq_num is int?
        header[5] = (seq_num >> 40) & 0xFF
        header[6] = (seq_num >> 32) & 0xFF
        header[7] = (seq_num >> 24) & 0xFF
        header[8] = (seq_num >> 16) & 0xFF
        header[9] = (seq_num >> 8) & 0xFF
        header[10] = seq_num & 0xFF
        
        struct.pack_into('!H', header, 11, length)
        
        return bytes(header) + payload

    @staticmethod
    def unpack(data):
        if len(data) < 13:
            raise ValueError("Record Header truncated")
        
        content_type = data[0]
        version = struct.unpack('!H', data[1:3])[0]
        epoch = struct.unpack('!H', data[3:5])[0]
        
        # Unpack 6-byte seq num
        seq_num_bytes = data[5:11]
        seq_num = int.from_bytes(seq_num_bytes, 'big')
        
        length = struct.unpack('!H', data[11:13])[0]
        
        payload = data[13:13+length]
        
        if len(payload) != length:
            pass # warning?
            
        return content_type, epoch, seq_num, payload

class DtlsHandshakeMessage:
    # Handshake Header:
    # MsgType(1) | Length(3) | MsgSeq(2) | FragOffset(3) | FragLen(3)
    # Total 12 bytes
    # For simplicity, we assume no fragmentation in our implementation for now (offset=0, fraglen=len)
    
    @staticmethod
    def pack(msg_type, msg_seq, payload):
        length = len(payload)
        header = bytearray(12)
        header[0] = msg_type
        
        # Length (24-bit)
        header[1] = (length >> 16) & 0xFF
        header[2] = (length >> 8) & 0xFF
        header[3] = length & 0xFF
        
        # MsgSeq
        struct.pack_into('!H', header, 4, msg_seq)
        
        # FragOffset (0)
        header[6] = 0
        header[7] = 0
        header[8] = 0
        
        # FragLen (length)
        header[9] = header[1]
        header[10] = header[2]
        header[11] = header[3]
        
        return bytes(header) + payload

    @staticmethod
    def unpack(data):
        if len(data) < 12:
            raise ValueError("Handshake Header truncated")
            
        msg_type = data[0]
        length = (data[1] << 16) | (data[2] << 8) | data[3]
        msg_seq = struct.unpack('!H', data[4:6])[0]
        
        # We ignore fragmentation info for now, as we reassemble or assume complete
        payload = data[12:12+length]
        
        return msg_type, msg_seq, payload
