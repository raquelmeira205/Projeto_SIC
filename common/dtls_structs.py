import struct
from enum import IntEnum

# Constantes DTLS
DTLS_VERSION = 0xFEFF # DTLS 1.0 (aprox) para simplicidade
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
    """
    Estrutura do Registro DTLS.
    Cabeçalho: ContentType(1) | Version(2) | Epoch(2) | SequenceNumber(6) | Length(2)
    """
    HEADER_SIZE = 13

    @staticmethod
    def pack(content_type, epoch, seq_num, payload):
        """Empacota um registro DTLS."""
        length = len(payload)
        
        # Empacotamento manual devido ao Sequence Number de 6 bytes
        header = bytearray(13)
        header[0] = content_type
        struct.pack_into('!H', header, 1, DTLS_VERSION)
        struct.pack_into('!H', header, 3, epoch)
        
        # Sequence Number (6 bytes)
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
        """Desempacota um registro DTLS."""
        if len(data) < 13:
            raise ValueError("Cabeçalho de Registro truncado")
        
        content_type = data[0]
        version = struct.unpack('!H', data[1:3])[0]
        epoch = struct.unpack('!H', data[3:5])[0]
        
        seq_num_bytes = data[5:11]
        seq_num = int.from_bytes(seq_num_bytes, 'big')
        
        length = struct.unpack('!H', data[11:13])[0]
        
        payload = data[13:13+length]
        
        return content_type, epoch, seq_num, payload

class DtlsHandshakeMessage:
    """
    Estrutura da Mensagem de Handshake DTLS.
    Cabeçalho: MsgType(1) | Length(3) | MsgSeq(2) | FragOffset(3) | FragLen(3)
    Total 12 bytes.
    """
    
    @staticmethod
    def pack(msg_type, msg_seq, payload):
        """Empacota uma mensagem de handshake."""
        length = len(payload)
        header = bytearray(12)
        header[0] = msg_type
        
        # Length (24-bit)
        header[1] = (length >> 16) & 0xFF
        header[2] = (length >> 8) & 0xFF
        header[3] = length & 0xFF
        
        # MsgSeq
        struct.pack_into('!H', header, 4, msg_seq)
        
        # FragOffset (0) - Sem fragmentação neste nível
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
        """Desempacota uma mensagem de handshake."""
        if len(data) < 12:
            raise ValueError("Cabeçalho de Handshake truncado")
            
        msg_type = data[0]
        length = (data[1] << 16) | (data[2] << 8) | data[3]
        msg_seq = struct.unpack('!H', data[4:6])[0]
        
        payload = data[12:12+length]
        
        return msg_type, msg_seq, payload
