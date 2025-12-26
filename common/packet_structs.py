import struct
from enum import IntEnum

class MsgType(IntEnum):
    DATA = 1
    HEARTBEAT = 2
    CONTROL = 3
    DTLS_HANDSHAKE = 4  # DTLS handshake messages (end-to-end)

NID_SIZE = 16

class PacketHeader:
    # Header: Source(16) | Dest(16) | Type(1) | PayloadLen(2) | SeqNum(4) | MAC(32)
    FORMAT = f'!{NID_SIZE}s{NID_SIZE}sBHI32s' 
    SIZE = struct.calcsize(FORMAT)

    @staticmethod
    def pack(source_nid: bytes, dest_nid: bytes, msg_type: int, payload: bytes, seq_num: int = 0, mac: bytes = b'\x00'*32) -> bytes:
        payload_len = len(payload)
        header = struct.pack(
            PacketHeader.FORMAT,
            source_nid,
            dest_nid,
            msg_type,
            payload_len,
            seq_num,
            mac
        )
        return header + payload
    
    @staticmethod
    def unpack(data: bytes):
        if len(data) < PacketHeader.SIZE:
            raise ValueError("Pacote demasiado curto")
        
        header_bytes = data[:PacketHeader.SIZE]
        payload_bytes = data[PacketHeader.SIZE:]

        src_nid, dest_nid, msg_type, payload_len, seq_num, mac = struct.unpack(PacketHeader.FORMAT, header_bytes)

        if len(payload_bytes) != payload_len:
            print(f"Aviso: Tamanho do payload ({len(payload_bytes)}) difere do declarado ({payload_len})")

        return src_nid, dest_nid, msg_type, payload_bytes, seq_num, mac
    
class HeartbeatPayload:

    @staticmethod
    def pack(sequence_number, signature):
        return struct.pack('!I', sequence_number) + signature

    @staticmethod
    def unpack(payload):
        seq_num = struct.unpack('!I', payload[:4])[0]
        signature = payload[4:]
        return seq_num, signature